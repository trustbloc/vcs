/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/lifecycle"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

var logger = log.New("event-bus")

const (
	defaultBufferSize = 250
)

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	TLSConfig      *tls.Config
	CMD            *cobra.Command
	CSLStore       credentialstatus.CSLStore
	ProfileService profileService
	KMSRegistry    kmsRegistry
	Crypto         vcCrypto
	Tracer         trace.Tracer
	IsTraceEnabled bool
	DocumentLoader ld.DocumentLoader
}

// Bus implements a publisher/subscriber using Go channels. This implementation
// works only on a single node, i.e. handlers are not distributed. In order to distribute
// the load across a cluster, a persistent message queue (such as RabbitMQ or Kafka) should
// instead be used.
type Bus struct {
	*lifecycle.Lifecycle
	Config

	subscribers map[string][]chan *spi.Event
	mutex       sync.RWMutex

	publishChan chan *entry
	doneChan    chan struct{}
}

type entry struct {
	topic    string
	messages []*spi.Event
}

// NewEventBus returns in-memory event bus.
func NewEventBus(cfg Config) *Bus {
	m := &Bus{
		Config:      cfg,
		subscribers: make(map[string][]chan *spi.Event),
		publishChan: make(chan *entry, defaultBufferSize),
		doneChan:    make(chan struct{}),
	}

	m.Lifecycle = lifecycle.New("event-bus", lifecycle.WithStop(m.stop))

	go m.processMessages()

	// start the service immediately
	m.Start()

	return m
}

// Close closes all resources.
func (b *Bus) Close() error {
	b.Stop()

	return nil
}

// IsConnected return true is connected.
func (b *Bus) IsConnected() bool {
	return true
}

func (b *Bus) stop() {
	logger.Info("stopping publisher/subscriber...")

	b.doneChan <- struct{}{}

	logger.Debug("... waiting for publisher to stop...")

	<-b.doneChan

	logger.Debug("... closing subscriber channels...")

	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, msgChans := range b.subscribers {
		for _, msgChan := range msgChans {
			close(msgChan)
		}
	}

	b.subscribers = nil

	logger.Info("... publisher/subscriber stopped.")
}

// Subscribe subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (b *Bus) Subscribe(_ context.Context, topic string) (<-chan *spi.Event, error) {
	if b.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	logger.Debug("subscribing to topic", log.WithTopic(topic))

	b.mutex.Lock()
	defer b.mutex.Unlock()

	msgChan := make(chan *spi.Event, defaultBufferSize)

	b.subscribers[topic] = append(b.subscribers[topic], msgChan)

	return msgChan, nil
}

// Publish publishes the given messages to the given topic. This function returns
// immediately after sending the messages to the Go channel(s), although it will
// block if the concurrency limit (defined by Config.Concurrency) has been reached.
func (b *Bus) Publish(_ context.Context, topic string, messages ...*spi.Event) error {
	if b.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	b.publishChan <- &entry{
		topic:    topic,
		messages: messages,
	}

	return nil
}

func (b *Bus) processMessages() {
	for {
		select {
		case entry := <-b.publishChan:
			b.publish(entry)

		case <-b.doneChan:
			b.doneChan <- struct{}{}

			logger.Debug("... publisher has stopped")

			return
		}
	}
}

func (b *Bus) publish(entry *entry) {
	b.mutex.RLock()
	subscribers := b.subscribers[entry.topic]
	b.mutex.RUnlock()

	if len(subscribers) == 0 {
		logger.Debug("no subscribers for topic", log.WithTopic(entry.topic))

		return
	}

	for _, subscriber := range subscribers {
		for _, m := range entry.messages {
			msg := m.Copy()

			logger.Debug("publishing message", logfields.WithEvent(msg))

			subscriber <- msg
		}
	}
}
