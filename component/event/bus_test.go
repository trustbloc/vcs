/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"
	"errors"
	"fmt"
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
	eb := NewEventBus(Config{})
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

		msg := spi.NewEventWithPayload(uuid, sourceURL, eventType, []byte(jsonMsg))

		require.NoError(t, eb.Publish(context.Background(), topic, msg))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		m, ok := receivedMessages[msg.ID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.ID, m.ID)
	})

	t.Run("success - no subscribers", func(t *testing.T) {
		msg := spi.NewEventWithPayload(uuid, sourceURL, eventType, []byte("{}"))

		require.NoError(t, eb.Publish(context.TODO(), "no-subscribers-topic", msg))

		time.Sleep(1000 * time.Millisecond)
	})

	require.NoError(t, eb.Close())
}

func TestEventBus_Error(t *testing.T) {
	t.Run("error - subscribe when closed", func(t *testing.T) {
		eb := NewEventBus(Config{})
		require.NotNil(t, eb)
		require.NoError(t, eb.Close())

		msgChan, err := eb.Subscribe(context.Background(), topic)
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
		require.Nil(t, msgChan)
	})

	t.Run("error - publish when closed", func(t *testing.T) {
		eb := NewEventBus(Config{})
		require.NotNil(t, eb)
		require.NoError(t, eb.Close())

		err := eb.Publish(context.Background(), topic, spi.NewEventWithPayload(uuid, sourceURL, eventType, []byte(jsonMsg)))
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
	})
}

func TestEventBus_Close(t *testing.T) {
	eb := NewEventBus(Config{})
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
			msg := spi.NewEventWithPayload(fmt.Sprintf("%s-%d", uuid, i), sourceURL, eventType, []byte(jsonMsg))

			if err := eb.Publish(context.TODO(), topic, msg); err != nil {
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
			if _, err := eb.Subscribe(context.TODO(), topic); err != nil {
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
	eb := NewEventBus(Config{})
	require.NotNil(t, eb)

	require.True(t, eb.IsConnected())
}
