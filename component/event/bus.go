/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/lifecycle"
)

var logger = log.New("event-bus")

const (
	defaultBufferSize = 250
)

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	TLSConfig *tls.Config
	CMD       *cobra.Command
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
	logger.Infof("stopping publisher/subscriber...")

	b.doneChan <- struct{}{}

	logger.Debugf("... waiting for publisher to stop...")

	<-b.doneChan

	logger.Debugf("... closing subscriber channels...")

	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, msgChans := range b.subscribers {
		for _, msgChan := range msgChans {
			close(msgChan)
		}
	}

	b.subscribers = nil

	logger.Infof("... publisher/subscriber stopped.")
}

// Subscribe subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (b *Bus) Subscribe(_ context.Context, topic string, _ ...spi.Option) (<-chan *spi.Event, error) {
	if b.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	logger.Debugf("subscribing to topic [%s]", topic)

	b.mutex.Lock()
	defer b.mutex.Unlock()

	msgChan := make(chan *spi.Event, defaultBufferSize)

	b.subscribers[topic] = append(b.subscribers[topic], msgChan)

	return msgChan, nil
}

// Publish publishes the given messages to the given topic. This function returns
// immediately after sending the messages to the Go channel(s), although it will
// block if the concurrency limit (defined by Config.Concurrency) has been reached.
func (b *Bus) Publish(topic string, messages ...*spi.Event) error {
	if b.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	b.publishChan <- &entry{
		topic:    topic,
		messages: messages,
	}

	return nil
}

// PublishWithOpts simply calls Publish since options are not supported.
func (b *Bus) PublishWithOpts(topic string, msg *spi.Event, _ ...spi.Option) error {
	return b.Publish(topic, msg)
}

func (b *Bus) processMessages() {
	for {
		select {
		case entry := <-b.publishChan:
			b.publish(entry)

		case <-b.doneChan:
			b.doneChan <- struct{}{}

			logger.Debugf("... publisher has stopped")

			return
		}
	}
}

func (b *Bus) publish(entry *entry) {
	b.mutex.RLock()
	subscribers := b.subscribers[entry.topic]
	b.mutex.RUnlock()

	if len(subscribers) == 0 {
		logger.Debugf("no subscribers for topic [%s]", entry.topic)

		return
	}

	for _, subscriber := range subscribers {
		for _, m := range entry.messages {
			msg := m.Copy()

			logger.Debugf("publishing message [%s]", msg)

			subscriber <- msg
		}
	}
}
