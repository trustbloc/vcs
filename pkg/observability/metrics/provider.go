/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"net/http"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
)

// Logger used by different metrics provider.
var Logger = log.New("metrics-provider")

// Constants used by different metrics provider.
const (
	// Namespace Organization namespace.
	Namespace = "vcs"

	// Crypto plain crypto operations.
	Crypto               = "crypto"
	CryptoSignTimeMetric = "crypto_sign_seconds"

	// Controller operations.
	Controller                    = "controller"
	ControllerCheckAuthRespMetric = "controller_checkAuthResponse_seconds"

	// Service operations.
	Service      = "service"
	VerifyOIDCVP = "service_verifyOIDCVerifiablePresentation_seconds"

	// HTTPServer HTTP server subsystem.
	HTTPServer = "httpserver"

	// HTTPClient HTTP client subsystem.
	HTTPClient                 = "httpclient"
	HTTPClientInFlightRequests = "in_flight_requests"
	HTTPClientTotalRequests    = "requests_total"
	HTTPClientRequestDuration  = "request_duration_seconds"
)

// ClientID defines the ID of the client.
type ClientID string

const (
	ClientPreAuth                    ClientID = "preauthorize"
	ClientIssuerProfile              ClientID = "issuer-profile"
	ClientVerifierProfile            ClientID = "verifier-profile"
	ClientCredentialStatus           ClientID = "credential-status" //nolint:gosec
	ClientOIDC4CI                    ClientID = "oidc4ci"
	ClientOIDC4CIV1                  ClientID = "oidc4civ1"
	ClientOIDC4PV1                   ClientID = "oidc4pv1"
	ClientWellKnown                  ClientID = "wellknown"
	ClientIssuerInteraction          ClientID = "issuer-interaction"
	ClientCredentialVerifier         ClientID = "credential-verifier" //nolint:gosec
	ClientDiscoverableClientIDScheme ClientID = "discoverable-client-id-scheme"
	ClientAttestationService         ClientID = "client-attestation-service"
)

// Provider is an interface for metrics provider.
type Provider interface {
	// Create creates a metrics provider instance
	Create() error
	// Destroy destroys the metrics provider instance
	Destroy() error
	// Metrics providers metrics
	Metrics(
		version string,
		domain string,
		scope string,
	) Metrics
}

// Metrics is an interface for the metrics to be supported by the provider.
//
//nolint:interfacebloat
type Metrics interface {
	SignTime(value time.Duration)
	CheckAuthorizationResponseTime(value time.Duration)
	VerifyOIDCVerifiablePresentationTime(value time.Duration)

	InstrumentHTTPTransport(ClientID, http.RoundTripper) http.RoundTripper
}
