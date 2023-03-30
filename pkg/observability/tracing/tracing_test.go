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
		shutdown, tracer, err := Initialize("", "service1")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		require.NotNil(t, tracer)
		require.NotPanics(t, shutdown)
	})

	t.Run("Provider JAEGER", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_JAEGER_ENDPOINT", "localhost")

		shutdown, tracer, err := Initialize("JAEGER", "service1")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		require.NotNil(t, tracer)
		require.NotPanics(t, shutdown)
	})

	t.Run("Provider STDOUT", func(t *testing.T) {
		shutdown, tracer, err := Initialize("STDOUT", "service1")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		require.NotNil(t, tracer)
		require.NotPanics(t, shutdown)
	})

	t.Run("Unsupported provider", func(t *testing.T) {
		shutdown, tracer, err := Initialize("unsupported", "service1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported exporter type")
		require.Nil(t, shutdown)
		require.Nil(t, tracer)
	})
}
