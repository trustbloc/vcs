/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
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
)

// Provider is an interface for metrics provider.
type Provider interface {
	// Create creates a metrics provider instance
	Create() error
	// Destroy destroys the metrics provider instance
	Destroy() error
	// Metrics providers metrics
	Metrics() Metrics
}

// Metrics is an interface for the metrics to be supported by the provider.
//
//nolint:interfacebloat
type Metrics interface {
	SignTime(value time.Duration)
	CheckAuthorizationResponseTime(value time.Duration)
	VerifyOIDCVerifiablePresentationTime(value time.Duration)
}
