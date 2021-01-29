/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

// Operation defines handlers for comparator service.
type Operation struct{}

// Config defines configuration for comparator operations.
type Config struct{}

// New returns operation instance.
func New(cfg *Config) (*Operation, error) {
	return &Operation{}, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{}
}
