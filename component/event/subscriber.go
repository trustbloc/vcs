/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"fmt"

	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/lifecycle"
)

type (
	eventHandler func(event *spi.Event) error
)

type eventSubscriber interface {
	Subscribe(ctx context.Context, topic string) (<-chan *spi.Event, error)
}

// Subscriber implements an event subscriber.
type Subscriber struct {
	*lifecycle.Lifecycle

	subscriber eventSubscriber
	handler    eventHandler

	eventChan <-chan *spi.Event
}

// NewEventSubscriber returns a new subscriber.
func NewEventSubscriber(sub eventSubscriber, topic string, handler eventHandler) (*Subscriber, error) {
	h := &Subscriber{
		subscriber: sub,
		handler:    handler,
	}

	h.Lifecycle = lifecycle.New("event-subscriber",
		lifecycle.WithStart(h.start),
	)

	logger.Debug("subscribing to topic", log.WithTopic(topic))

	ch, err := sub.Subscribe(context.Background(), topic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	h.eventChan = ch

	return h, nil
}

func (h *Subscriber) start() {
	go h.listen()
}

func (h *Subscriber) listen() {
	logger.Debug("starting event listener...")

	for { //nolint:gosimple
		select {
		case e, ok := <-h.eventChan:
			if !ok {
				logger.Info("event channel closed")

				return
			}

			logger.Debug("received new event", log.WithID(e.ID), logfields.WithEvent(e))

			h.handleEvent(e)
		}
	}
}

func (h *Subscriber) handleEvent(e *spi.Event) {
	logger.Debug("handling subscriber event ", log.WithID(e.ID), logfields.WithEvent(e))

	err := h.handler(e)
	if err != nil {
		logger.Error("failed to handle event", log.WithID(e.ID), log.WithError(err))
	}
}
