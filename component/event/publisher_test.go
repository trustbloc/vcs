/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

func TestEventPublisher(t *testing.T) {
	source, err := url.Parse("https://test.com")
	require.NoError(t, err)

	t.Run("success - return channel", func(t *testing.T) {
		eventBus := NewEventBus(DefaultConfig())

		ch1, err := eventBus.Subscribe(nil, topic)
		require.NoError(t, err)

		publisher := NewEventPublisher(eventBus)

		require.NoError(t, publisher.Publish(topic, spi.NewEvent("id-1", source, eventType, []byte(jsonMsg))))

		_, err = eventBus.Subscribe(nil, topic)
		require.NoError(t, err)

		require.NoError(t, publisher.Publish(topic, spi.NewEvent("id-2", source, eventType, []byte(jsonMsg))))
		require.NoError(t, publisher.Publish(topic, spi.NewEvent("id-3", source, eventType, []byte(jsonMsg))))

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
				fmt.Printf("exiting...")

				return
			}
		}
	})
}

func printChannelEvent(ch string, e *spi.Event) {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		fmt.Printf(err.Error())
	}

	fmt.Printf("Channel: %s; Event: %s\n", ch, eventBytes)
}
