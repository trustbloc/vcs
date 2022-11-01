/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)

	t.Run("VCS Activity", func(t *testing.T) {
		require.NotPanics(t, func() { m.SignCount() })
		require.NotPanics(t, func() { m.SignTime(time.Second) })
	})
}
