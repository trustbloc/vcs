/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	m := GetMetrics()
	require.NotNil(t, m)
	require.True(t, m == GetMetrics())

	t.Run("VCS Activity", func(t *testing.T) {
		require.NotPanics(t, func() { m.SignCount() })
		require.NotPanics(t, func() { m.SignTime(time.Second) })
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
