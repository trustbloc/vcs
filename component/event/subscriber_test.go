/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/component/event/mocks"
	"github.com/trustbloc/vcs/pkg/event/spi"
)

//go:generate counterfeiter -o ./mocks/subscriber.gen.go --fake-name EventSubscriber . eventSubscriber

func TestEventSubscriber(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		eventBus := NewEventBus(Config{})

		subscriber, err := NewEventSubscriber(eventBus, topic, printEvent)
		require.NoError(t, err)

		subscriber.Start()

		publisher := NewEventPublisher(eventBus)

		require.NoError(t, publisher.Publish(topic, spi.NewEventWithPayload("id-1", sourceURL, eventType, []byte(jsonMsg))))
		require.NoError(t, publisher.Publish(topic, spi.NewEventWithPayload("id-2", sourceURL, eventType, []byte(jsonMsg))))
		require.NoError(t, publisher.Publish(topic, spi.NewEventWithPayload("id-3", sourceURL, eventType, []byte(jsonMsg))))

		time.Sleep(time.Second)
	})

	t.Run("error - event bus stopped/channel closed error", func(t *testing.T) {
		eventBus := NewEventBus(Config{})

		subscriber, err := NewEventSubscriber(eventBus, topic, printEvent)
		require.NoError(t, err)

		subscriber.Start()

		publisher := NewEventPublisher(eventBus)

		require.NoError(t, publisher.Publish(topic, spi.NewEventWithPayload("id-1", sourceURL, eventType, []byte(jsonMsg))))

		time.Sleep(time.Second)

		eventBus.Stop()

		time.Sleep(1 * time.Second)
	})

	t.Run("error - event handler error", func(t *testing.T) {
		eventBus := NewEventBus(Config{})

		subscriber, err := NewEventSubscriber(eventBus, topic, errorEvent)
		require.NoError(t, err)

		subscriber.Start()

		publisher := NewEventPublisher(eventBus)

		require.NoError(t, publisher.Publish(topic, spi.NewEventWithPayload("id-1", sourceURL, eventType, []byte(jsonMsg))))

		time.Sleep(time.Second)
	})

	t.Run("error - subscribe error", func(t *testing.T) {
		eventBus := &mocks.EventSubscriber{}
		eventBus.SubscribeReturns(nil, fmt.Errorf("subscription error"))

		subscriber, err := NewEventSubscriber(eventBus, topic, printEvent)
		require.Error(t, err)
		require.Nil(t, subscriber)
		require.Contains(t, err.Error(), "subscription error")
	})
}

func printEvent(e *spi.Event) error {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return err
	}

	fmt.Printf("Event: %s\n", eventBytes) //nolint: forbidigo

	return nil
}

func errorEvent(_ *spi.Event) error {
	return fmt.Errorf("event error")
}
