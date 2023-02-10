/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitialize(t *testing.T) {
	t.Run("Provider NONE", func(t *testing.T) {
		shutdown, tracer, err := Initialize(ProviderNone, "service1", "")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		require.NotNil(t, tracer)
		require.NotPanics(t, shutdown)
	})

	t.Run("Provider JAEGER", func(t *testing.T) {
		shutdown, tracer, err := Initialize(ProviderJaeger, "service1", "")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		require.NotNil(t, tracer)
		require.NotPanics(t, shutdown)
	})

	t.Run("Unsupported provider", func(t *testing.T) {
		shutdown, tracer, err := Initialize("unsupported", "service1", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported tracing provider")
		require.Nil(t, shutdown)
		require.Nil(t, tracer)
	})
}
