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

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/observability/metrics"
)

var logger = metrics.Logger

const (
	clientIDLabel = "clientID"
	codeLabel     = "code"
	methodLabel   = "method"
)

var (
	createOnce sync.Once       //nolint:gochecknoglobals
	instance   metrics.Metrics //nolint:gochecknoglobals
)

type promProvider struct {
	httpServer *echo.Echo
}

// NewPrometheusProvider creates new instance of Prometheus Metrics Provider.
func NewPrometheusProvider(httpServer *echo.Echo) metrics.Provider {
	return &promProvider{httpServer: httpServer}
}

// Create creates/initializes the prometheus metrics provider.
func (pp *promProvider) Create() error {
	if pp.httpServer == nil {
		return fmt.Errorf("metrics HTTP server is nil, cannot start it")
	}

	pp.httpServer.GET("/metrics", func(c echo.Context) error {
		promhttp.HandlerFor(prometheus.DefaultGatherer,
			promhttp.HandlerOpts{
				// Opt into OpenMetrics to support exemplars.
				EnableOpenMetrics: true,
			},
		).ServeHTTP(c.Response().Writer, c.Request())
		return nil
	})

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
	httpInFlight        map[metrics.ClientID]prometheus.Gauge
	httpTotalRequests   map[metrics.ClientID]*prometheus.CounterVec
	httpRequestDuration map[metrics.ClientID]prometheus.ObserverVec

	signTime          prometheus.Histogram
	checkAuthRespTime prometheus.Histogram
	verifyOIDCVPTime  prometheus.Histogram
}

// NewMetrics creates instance of prometheus metrics.
func NewMetrics() metrics.Metrics {
	httpClients := []metrics.ClientID{
		metrics.ClientPreAuth, metrics.ClientCredentialStatus,
		metrics.ClientIssuerProfile, metrics.ClientVerifierProfile,
		metrics.ClientIssuerInteraction, metrics.ClientOIDC4PV1,
		metrics.ClientOIDC4CI, metrics.ClientOIDC4CIV1,
		metrics.ClientWellKnown, metrics.ClientCredentialVerifier,
	}

	pm := &PromMetrics{
		httpInFlight:        newHTTPClientInFlightRequests(httpClients),
		httpTotalRequests:   newHTTPClientTotalRequests(httpClients),
		httpRequestDuration: newHTTPClientRequestTime(httpClients),

		signTime:          newSignTime(),
		checkAuthRespTime: newCheckAuthRespTime(),
		verifyOIDCVPTime:  newVerifyOIDCVPTime(),
	}

	pm.register()

	return pm
}

// SignTime records the time for sign.
func (pm *PromMetrics) SignTime(value time.Duration) {
	pm.signTime.Observe(value.Seconds())

	logger.Debug("crypto sign time", log.WithDuration(value))
}

// CheckAuthorizationResponseTime records the time for CheckAuthorizationResponse controller endpoint call.
func (pm *PromMetrics) CheckAuthorizationResponseTime(value time.Duration) {
	pm.signTime.Observe(value.Seconds())

	logger.Debug("CheckAuthorizationResponse controller endpoint time", log.WithDuration(value))
}

func (pm *PromMetrics) VerifyOIDCVerifiablePresentationTime(value time.Duration) {
	pm.verifyOIDCVPTime.Observe(value.Seconds())

	logger.Debug("VerifyOIDCVerifiablePresentation service call time", log.WithDuration(value))
}

// InstrumentHTTPTransport instruments the given HTTP transport with metrics such as
// request duration, number of in-flight requests, etc.
func (pm *PromMetrics) InstrumentHTTPTransport(id metrics.ClientID, transport http.RoundTripper) http.RoundTripper {
	inFlight := pm.httpInFlight[id]
	totalRequests := pm.httpTotalRequests[id]
	requestDuration := pm.httpRequestDuration[id]

	if inFlight == nil || totalRequests == nil || requestDuration == nil {
		panic(fmt.Sprintf("client not found for HTTP client metric [%s]", id))
	}

	return promhttp.InstrumentRoundTripperInFlight(inFlight,
		promhttp.InstrumentRoundTripperCounter(totalRequests,
			promhttp.InstrumentRoundTripperDuration(requestDuration, transport),
		),
	)
}

func (pm *PromMetrics) register() {
	prometheus.MustRegister(
		pm.signTime, pm.checkAuthRespTime, pm.verifyOIDCVPTime,
	)

	for _, m := range pm.httpInFlight {
		prometheus.MustRegister(m)
	}

	for _, m := range pm.httpTotalRequests {
		prometheus.MustRegister(m)
	}

	for _, m := range pm.httpRequestDuration {
		prometheus.MustRegister(m)
	}
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

func newCounterVec(subsystem, name, help string, labels prometheus.Labels, varLabels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	}, varLabels)
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

func newHistogramVec(subsystem, name, help string, labels prometheus.Labels,
	varLabels ...string) prometheus.ObserverVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	}, varLabels)
}

func newSignTime() prometheus.Histogram {
	return newHistogram(
		metrics.Crypto, metrics.CryptoSignTimeMetric,
		"The time (in seconds) it takes to run crypto sign.",
		nil,
	)
}

func newCheckAuthRespTime() prometheus.Histogram {
	return newHistogram(
		metrics.Controller, metrics.ControllerCheckAuthRespMetric,
		"The time (in seconds) it takes to execute checkAuthorizationResponse controller endpoint call.",
		nil,
	)
}

func newVerifyOIDCVPTime() prometheus.Histogram {
	return newHistogram(
		metrics.Service, metrics.VerifyOIDCVP,
		"The time (in seconds) it takes to execute VerifyOIDCVerifiablePresentation service call.",
		nil,
	)
}

func newHTTPClientInFlightRequests(clients []metrics.ClientID) map[metrics.ClientID]prometheus.Gauge {
	m := make(map[metrics.ClientID]prometheus.Gauge)

	for _, id := range clients {
		m[id] = newGauge(metrics.HTTPClient, metrics.HTTPClientInFlightRequests,
			"The number of in-flight requests for the HTTP client.",
			prometheus.Labels{clientIDLabel: string(id)})
	}

	return m
}

func newHTTPClientTotalRequests(clients []metrics.ClientID) map[metrics.ClientID]*prometheus.CounterVec {
	m := make(map[metrics.ClientID]*prometheus.CounterVec)

	for _, id := range clients {
		m[id] = newCounterVec(metrics.HTTPClient, metrics.HTTPClientTotalRequests,
			"The total number of requests for the HTTP client.",
			prometheus.Labels{clientIDLabel: string(id)}, codeLabel, methodLabel)
	}

	return m
}

func newHTTPClientRequestTime(clients []metrics.ClientID) map[metrics.ClientID]prometheus.ObserverVec {
	m := make(map[metrics.ClientID]prometheus.ObserverVec)

	for _, id := range clients {
		m[id] = newHistogramVec(metrics.HTTPClient, metrics.HTTPClientRequestDuration,
			"The duration (in seconds) of an HTTP request.",
			prometheus.Labels{clientIDLabel: string(id)}, methodLabel,
		)
	}

	return m
}
