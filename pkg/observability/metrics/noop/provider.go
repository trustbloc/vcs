/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"time"

	"github.com/trustbloc/vcs/pkg/observability/metrics"
)

// NoMetrics provides default no operation implementation for the NoMetrics interface.
type NoMetrics struct{}

// GetMetrics returns metrics implementation.
func GetMetrics() metrics.Metrics {
	return &NoMetrics{}
}

func (n *NoMetrics) SignTime(_ time.Duration)                             {}
func (n *NoMetrics) CheckAuthorizationResponseTime(_ time.Duration)       {}
func (n *NoMetrics) VerifyOIDCVerifiablePresentationTime(_ time.Duration) {}
