/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/component/event/mocks"
	"github.com/trustbloc/vcs/pkg/event/spi"
)

//go:generate counterfeiter -o ./mocks/publisher.gen.go --fake-name EventPublisher . eventPublisher

func TestEventPublisher(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		eventBus := NewEventBus(Config{})

		ctx := context.TODO()

		ch1, err := eventBus.Subscribe(ctx, topic)
		require.NoError(t, err)

		publisher := NewEventPublisher(eventBus)

		require.NoError(t, publisher.Publish(ctx, topic,
			spi.NewEventWithPayload("id-1", sourceURL, eventType, []byte(jsonMsg))))

		_, err = eventBus.Subscribe(ctx, topic)
		require.NoError(t, err)

		require.NoError(t, publisher.Publish(ctx, topic,
			spi.NewEventWithPayload("id-2", sourceURL, eventType, []byte(jsonMsg))))
		require.NoError(t, publisher.Publish(ctx, topic,
			spi.NewEventWithPayload("id-3", sourceURL, eventType, []byte(jsonMsg))))

		done := make(chan interface{})

		go func() {
			time.Sleep(2 * time.Second)
			close(done)
		}()

		for {
			select {
			case d := <-ch1:
				go printChannelEvent("ch1", d)
			case <-done:
				fmt.Println("exiting...") //nolint: forbidigo

				return
			}
		}
	})

	t.Run("error - publish error", func(t *testing.T) {
		eventBus := &mocks.EventPublisher{}
		eventBus.PublishReturns(fmt.Errorf("publishing error"))

		publisher := NewEventPublisher(eventBus)

		err := publisher.Publish(context.TODO(), topic,
			spi.NewEventWithPayload("id-1", sourceURL, eventType, []byte(jsonMsg)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "publishing error")
	})
}

func printChannelEvent(ch string, e *spi.Event) {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		fmt.Println(err.Error()) //nolint:forbidigo
	}

	fmt.Printf("Channel: %s; Event: %s\n", ch, eventBytes) //nolint:forbidigo
}
