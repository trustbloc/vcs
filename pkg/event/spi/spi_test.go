/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvent(t *testing.T) {
	event := NewEvent("id", "source", "type")
	require.NotNil(t, event)

	payload, err := json.Marshal(map[string]interface{}{"k1": "v1"})
	require.NoError(t, err)

	eventWithPayload := NewEventWithPayload("id", "source", "type", payload)
	require.NotNil(t, eventWithPayload)

	eventCopy := event.Copy()
	require.NotNil(t, eventCopy)
}
