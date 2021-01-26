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
	operationID             = "/vaults"
	createVaultPath         = operationID
	saveDocPath             = operationID + "/{vaultID}/docs"
	getDocPath              = operationID + "/{vaultID}/docs/{docID}"
	createAuthorizationPath = operationID + "/{vaultID}/authorizations"
	getAuthorizationPath    = operationID + "/{vaultID}/authorizations/{authID}"
	deleteAuthorizationPath = operationID + "/{vaultID}/authorizations/{authID}"
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
		support.NewHTTPHandler(createVaultPath, http.MethodPost, o.CreateVault),
		support.NewHTTPHandler(saveDocPath, http.MethodPost, o.SaveDoc),
		support.NewHTTPHandler(getDocPath, http.MethodGet, o.GetDoc),
		support.NewHTTPHandler(createAuthorizationPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(getAuthorizationPath, http.MethodGet, o.GetAuthorization),
		support.NewHTTPHandler(deleteAuthorizationPath, http.MethodDelete, o.DeleteAuthorization),
	}
}

// CreateVault swagger:route POST /vaults vault createVaultReq
//
// Creates a new vault.
//
// Responses:
//    default: genericError
//        201: createVaultResp
func (o *Operation) CreateVault(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusCreated)
}

// SaveDoc swagger:route POST /vaults/{vaultID}/docs vault saveDocReq
//
// Encrypts and stores the document in the vault.
//
// Responses:
//    default: genericError
//        201: saveDocResp
func (o *Operation) SaveDoc(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusCreated)
}

// GetDoc swagger:route GET /vaults/{vaultID}/docs/{docID} vault getDocReq
//
// Returns the plaintext document by given ID.
//
// Responses:
//    default: genericError
//        200: getDocResp
func (o *Operation) GetDoc(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

// CreateAuthorization swagger:route POST /vaults/{vaultID}/authorizations vault createAuthorizationReq
//
// Creates an authorization.
//
// Responses:
//    default: genericError
//        201: createAuthorizationResp
func (o *Operation) CreateAuthorization(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusCreated)
}

// GetAuthorization swagger:route GET /vaults/{vaultID}/authorizations/{authID} vault getAuthorizationReq
//
// Fetches an authorization.
//
// Responses:
//    default: genericError
//        200: getAuthorizationResp
func (o *Operation) GetAuthorization(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

// DeleteAuthorization swagger:route DELETE /vaults/{vaultID}/authorizations/{authID} vault deleteAuthorizationReq
//
// Deletes an authorization.
//
// Responses:
//    default: genericError
//        200: deleteAuthorizationResp
func (o *Operation) DeleteAuthorization(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}
