/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/lifecycle"
)

const (
	uuid      = "uuid"
	jsonMsg   = "{}"
	sourceURL = "https://test.com"
	topic     = "test-topic"
	eventType = "publisher.transaction.v1"
)

func TestEventBus_Publish(t *testing.T) {
	source, err := url.Parse(sourceURL)
	require.NoError(t, err)

	cfg := DefaultConfig()

	eb := NewEventBus(cfg)
	require.NotNil(t, eb)

	t.Run("success", func(t *testing.T) {
		msgChan, err := eb.Subscribe(context.Background(), topic)
		require.NoError(t, err)

		var mutex sync.Mutex
		receivedMessages := make(map[string]*spi.Event)

		go func() {
			for msg := range msgChan {

				mutex.Lock()
				receivedMessages[msg.ID] = msg
				mutex.Unlock()
			}
		}()

		msg := spi.NewEvent(uuid, source, eventType, []byte(jsonMsg))

		require.NoError(t, eb.Publish(topic, msg))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		m, ok := receivedMessages[msg.ID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.ID, m.ID)
	})

	t.Run("success - no subscribers", func(t *testing.T) {
		msg := spi.NewEvent(uuid, source, eventType, []byte("{}"))

		require.NoError(t, eb.PublishWithOpts("no-subscribers-topic", msg, spi.WithDeliveryDelay(5*time.Second)))

		time.Sleep(1000 * time.Millisecond)
	})

	require.NoError(t, eb.Close())
}

func TestEventBus_Error(t *testing.T) {
	source, err := url.Parse(sourceURL)
	require.NoError(t, err)

	t.Run("error - subscribe when closed", func(t *testing.T) {
		eb := NewEventBus(DefaultConfig())
		require.NotNil(t, eb)
		require.NoError(t, eb.Close())

		msgChan, err := eb.Subscribe(context.Background(), topic)
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
		require.Nil(t, msgChan)
	})

	t.Run("error - publish when closed", func(t *testing.T) {
		eb := NewEventBus(DefaultConfig())
		require.NotNil(t, eb)
		require.NoError(t, eb.Close())

		err := eb.Publish(topic, spi.NewEvent(uuid, source, eventType, []byte(jsonMsg)))
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
	})
}

func TestEventBus_Close(t *testing.T) {
	source, err := url.Parse(sourceURL)
	require.NoError(t, err)

	eb := NewEventBus(DefaultConfig())
	require.NotNil(t, eb)

	msgChan, err := eb.Subscribe(context.Background(), topic)
	require.NoError(t, err)

	var mutex sync.Mutex

	receivedMessages := make(map[string]*spi.Event)

	go func() {
		for msg := range msgChan {
			time.Sleep(5 * time.Millisecond)

			mutex.Lock()
			receivedMessages[msg.ID] = msg
			mutex.Unlock()
		}
	}()

	go func() {
		for i := 0; i < 250; i++ {
			msg := spi.NewEvent(fmt.Sprintf("%s-%d", uuid, i), source, eventType, []byte(jsonMsg))

			if err := eb.PublishWithOpts(topic, msg); err != nil {
				if errors.Is(err, lifecycle.ErrNotStarted) {
					return
				}

				panic(err)
			}

			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		for i := 0; i < 500; i++ {
			if _, err := eb.Subscribe(nil, topic); err != nil {
				if errors.Is(err, lifecycle.ErrNotStarted) {
					return
				}

				panic(err)
			}

			time.Sleep(3 * time.Millisecond)
		}
	}()

	time.Sleep(1 * time.Second)

	// Close the service while we're still publishing messages to ensure
	// we don't panic or encounter race conditions.
	require.NoError(t, eb.Close())

	mutex.Lock()
	t.Logf("Received %d messages", len(receivedMessages))
	mutex.Unlock()
}

func TestEventBus_IsConnected(t *testing.T) {
	eb := NewEventBus(DefaultConfig())
	require.NotNil(t, eb)

	require.True(t, eb.IsConnected())
}
