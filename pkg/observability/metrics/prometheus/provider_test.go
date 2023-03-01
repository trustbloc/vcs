/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
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
