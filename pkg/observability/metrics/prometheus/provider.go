/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/trustbloc/vcs/internal/pkg/log"
	"github.com/trustbloc/vcs/pkg/observability/metrics"
)

var logger = metrics.Logger

var (
	createOnce sync.Once       //nolint:gochecknoglobals
	instance   metrics.Metrics //nolint:gochecknoglobals
)

type promProvider struct {
	httpServer *http.Server
}

// NewPrometheusProvider creates new instance of Prometheus Metrics Provider.
func NewPrometheusProvider(httpServer *http.Server) metrics.Provider {
	return &promProvider{httpServer: httpServer}
}

// Create creates/initializes the prometheus metrics provider.
func (pp *promProvider) Create() error {
	if pp.httpServer != nil {
		return nil
	}

	if err := pp.httpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("start metrics HTTP server: %w", err)
	}

	return nil
}

// Metrics returns supported metrics.
func (pp *promProvider) Metrics() metrics.Metrics {
	return GetMetrics()
}

// Destroy destroys the prometheus metrics provider.
func (pp *promProvider) Destroy() error {
	if pp.httpServer != nil {
		return pp.httpServer.Shutdown(context.Background())
	}

	return nil
}

// GetMetrics returns metrics implementation.
func GetMetrics() metrics.Metrics {
	createOnce.Do(func() {
		instance = NewMetrics()
	})

	return instance
}

// PromMetrics manages the metrics for VCS.
type PromMetrics struct {
	signCount prometheus.Counter
	signTime  prometheus.Histogram
}

// NewMetrics creates instance of prometheus metrics.
func NewMetrics() metrics.Metrics {
	pm := &PromMetrics{
		signCount: newSignCount(),
		signTime:  newSignTime(),
	}

	registerMetrics(pm)

	return pm
}

// SignCount increments the number of sign hits.
func (pm *PromMetrics) SignCount() {
	pm.signCount.Inc()
}

// SignTime records the time for sign.
func (pm *PromMetrics) SignTime(value time.Duration) {
	pm.signTime.Observe(value.Seconds())

	logger.Debug("crypto sign time", log.WithDuration(value))
}

func registerMetrics(pm *PromMetrics) {
	prometheus.MustRegister(
		pm.signCount, pm.signTime,
	)
}

func newCounter(subsystem, name, help string, labels prometheus.Labels) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newGauge(subsystem, name, help string, labels prometheus.Labels) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newHistogram(subsystem, name, help string, labels prometheus.Labels) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newSignCount() prometheus.Counter {
	return newCounter(
		metrics.Crypto, metrics.CryptoSignCountMetric,
		"The number of times crypto sign called.",
		nil,
	)
}

func newSignTime() prometheus.Histogram {
	return newHistogram(
		metrics.Crypto, metrics.CryptoSignTimeMetric,
		"The time (in seconds) it takes for crypto sign.",
		nil,
	)
}
