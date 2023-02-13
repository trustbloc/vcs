/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvent(t *testing.T) {
	event := NewEvent("id", "source", "type")
	require.NotNil(t, event)

	eventWithPayload := NewEventWithPayload("id", "source", "type", Payload("{}"))
	require.NotNil(t, eventWithPayload)

	eventCopy := event.Copy()
	require.NotNil(t, eventCopy)
}
