/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLifecycle(t *testing.T) {
	started := false
	stopped := false

	lc := New(
		"service1",
		WithStart(func() {
			started = true
		}),
		WithStop(func() {
			stopped = true
		}),
	)
	require.NotNil(t, lc)

	require.Equal(t, StateNotStarted, lc.State())

	lc.Start()
	require.True(t, started)
	require.Equal(t, StateStarted, lc.State())

	require.NotPanics(t, lc.Start)

	lc.Stop()
	require.True(t, stopped)
	require.Equal(t, StateStopped, lc.State())

	require.NotPanics(t, lc.Stop)
}
