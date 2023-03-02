/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/observability/metrics"
)

func TestMetrics(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)

	t.Run("VCS Activity", func(t *testing.T) {
		require.NotPanics(t, func() { m.SignTime(time.Second) })
		require.NotPanics(t, func() { m.CheckAuthorizationResponseTime(time.Second) })
		require.NotPanics(t, func() { m.VerifyOIDCVerifiablePresentationTime(time.Second) })
	})
}

func TestMetrics_InstrumentHTTPTransport(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)

	t1 := http.DefaultTransport

	t2 := m.InstrumentHTTPTransport(metrics.ClientVerifierProfile, t1)
	require.NotNil(t, t2)
	require.True(t, t1 == t2)
}
