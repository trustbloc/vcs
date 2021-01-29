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
	operationID       = "/hubstore/profiles"
	createProfilePath = operationID
	createQueryPath   = operationID + "/{profileID}/queries"
	createAuthzPath   = operationID + "/{profileID}/authorizations"

	comparePath = "/compare"
	extractPath = "/extract"
)

// Operation defines handlers for vault service.
type Operation struct{}

// Config defines configuration for vault operations.
type Config struct{}

// New returns operation instance.
func New(cfg *Config) (*Operation, error) {
	return &Operation{}, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(createProfilePath, http.MethodPost, o.CreateProfile),
		support.NewHTTPHandler(createQueryPath, http.MethodPost, o.CreateQuery),
		support.NewHTTPHandler(createAuthzPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(comparePath, http.MethodPost, o.Compare),
		support.NewHTTPHandler(extractPath, http.MethodGet, o.Extract),
	}
}

// CreateProfile swagger:route POST /hubstore/profiles createProfileReq
//
// Creates a Profile.
//
// Produces:
//   - application/json
// Responses:
//   201: createProfileResp
//   500: Error
func (o *Operation) CreateProfile(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

// CreateQuery swagger:route POST /hubstore/profiles/{profileID}/queries createQueryReq
//
// Creates a Query.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   201: createQueryResp
//   403: Error
//   500: Error
func (o *Operation) CreateQuery(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

// CreateAuthorization swagger:route POST /hubstore/profiles/{profileID}/authorizations createAuthorizationReq
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

// Compare swagger:route POST /hubstore/compare comparisonReq
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

// Extract swagger:route GET /hubstore/extract extractionReq
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
