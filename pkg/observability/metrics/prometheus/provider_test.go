/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"net/http"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/observability/metrics"
)

func TestPromProvider(t *testing.T) {
	provider := NewPrometheusProvider(echo.New())
	require.NotNil(t, provider)

	err := provider.Create()
	require.NoError(t, err)

	m := provider.Metrics()
	require.NotNil(t, m)

	err = provider.Destroy()
	require.NoError(t, err)
}

func TestMetrics(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)
	require.True(t, m == GetMetrics())

	t.Run("VCS Activity", func(t *testing.T) {
		require.NotPanics(t, func() { m.SignTime(time.Second) })
		require.NotPanics(t, func() { m.CheckAuthorizationResponseTime(time.Second) })
		require.NotPanics(t, func() { m.CheckAuthorizationResponseTime(time.Second) })
	})
}

func TestNewGauge(t *testing.T) {
	require.NotNil(t, newGauge("activityPub", "metric_name", "Some help", nil))
}

func TestNewCounter(t *testing.T) {
	labels := prometheus.Labels{"type": "create"}

	require.NotNil(t, newCounter("activityPub", "metric_name", "Some help", labels))
}

func TestNewHistogram(t *testing.T) {
	labels := prometheus.Labels{"type": "create"}

	require.NotNil(t, newHistogram("activityPub", "metric_name", "Some help", labels))
}

func TestMetrics_InstrumentHTTPTransport(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)

	t1 := http.DefaultTransport

	t2 := m.InstrumentHTTPTransport(metrics.ClientVerifierProfile, t1)
	require.NotNil(t, t2)
	require.False(t, t1 == t2)

	require.Panics(t, func() {
		m.InstrumentHTTPTransport("unknown", t1)
	})
}
