/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	createAuthzPath = "/authorizations"
	comparePath     = "/compare"
	extractPath     = "/extract"
	getConfigPath   = "/config"
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
	return []support.Handler{
		support.NewHTTPHandler(createAuthzPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(comparePath, http.MethodPost, o.Compare),
		support.NewHTTPHandler(extractPath, http.MethodPost, o.Extract),
		support.NewHTTPHandler(getConfigPath, http.MethodPost, o.Config),
	}
}

// CreateAuthorization swagger:route POST /authorizations createAuthorizationReq
//
// Creates an Authorization.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   201: createAuthorizationResp
//   403: Error
//   500: Error
func (o *Operation) CreateAuthorization(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

// Compare swagger:route POST /compare comparisonReq
//
// Performs a comparison.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   200: comparisonResp
//   500: Error
func (o *Operation) Compare(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Extract swagger:route POST /extract extractionReq
//
// Extracts the contents of a document.
//
// Produces:
//   - application/json
// Responses:
//   200: extractionResp
//   500: Error
func (o *Operation) Extract(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Config swagger:route GET /config configReq
//
// Get config.
//
// Produces:
//   - application/json
// Responses:
//   200: configResp
//   500: Error
func (o *Operation) Config(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
