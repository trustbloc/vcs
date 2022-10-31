/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/trustbloc/vcs/pkg/restapi/common"
)

// Handler implements a Prometheus /metrics endpoint.
type Handler struct{}

// NewHandler returns a new /metrics endpoint which returns Prometheus formatted statistics.
func NewHandler() *Handler {
	return &Handler{}
}

// Path returns the base path of the target URL for this Handler.
func (h *Handler) Path() string {
	return "/metrics"
}

// Method returns the HTTP method, which is always GET.
func (h *Handler) Method() string {
	return http.MethodGet
}

// Handler returns the Handler that should be invoked when an HTTP GET is requested to the target endpoint.
// This Handler must be registered with an HTTP server.
func (h *Handler) Handler() common.HTTPRequestHandler {
	ph := promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	)

	return func(writer http.ResponseWriter, request *http.Request) {
		ph.ServeHTTP(writer, request)
	}
}
