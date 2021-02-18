/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/messages"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

// API endpoints.
const (
	operationID             = "/vaults"
	CreateVaultPath         = operationID
	DeleteVaultPath         = operationID + "/{vaultID}"
	SaveDocPath             = operationID + "/{vaultID}/docs"
	GetDocMetadataPath      = operationID + "/{vaultID}/docs/{docID}/metadata"
	CreateAuthorizationPath = operationID + "/{vaultID}/authorizations"
	GetAuthorizationPath    = operationID + "/{vaultID}/authorizations/{authID}"
	DeleteAuthorizationPath = operationID + "/{vaultID}/authorizations/{authID}"
)

var logger = log.New("vault-operation")

// Operation defines handlers for vault service.
type Operation struct {
	vault      vault.Vault
	GenerateID func() (string, error)
}

// New returns operation instance.
func New(v vault.Vault) *Operation {
	return &Operation{
		vault:      v,
		GenerateID: edvutils.GenerateEDVCompatibleID,
	}
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(CreateVaultPath, http.MethodPost, o.CreateVault),
		support.NewHTTPHandler(DeleteVaultPath, http.MethodDelete, o.DeleteVault),
		support.NewHTTPHandler(SaveDocPath, http.MethodPost, o.SaveDoc),
		support.NewHTTPHandler(GetDocMetadataPath, http.MethodGet, o.GetDocMetadata),
		support.NewHTTPHandler(CreateAuthorizationPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(GetAuthorizationPath, http.MethodGet, o.GetAuthorization),
		support.NewHTTPHandler(DeleteAuthorizationPath, http.MethodDelete, o.DeleteAuthorization),
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
	result, err := o.vault.CreateVault()
	if err != nil {
		o.writeErrorResponse(rw, err, http.StatusInternalServerError)

		return
	}

	var resp createVaultResp
	resp.Body = result

	o.WriteResponse(rw, resp.Body, http.StatusCreated)
}

// DeleteVault swagger:route DELETE /vaults/{vaultID} vault deleteVaultReq
//
// Deletes an existing vault.
//
// Responses:
//    default: genericError
//        200: deleteVaultResp
func (o *Operation) DeleteVault(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

// SaveDoc swagger:route POST /vaults/{vaultID}/docs vault saveDocReq
//
// Creates or updates a document by encrypting it and storing it in the vault.
//
// Responses:
//    default: genericError
//        201: saveDocResp
func (o *Operation) SaveDoc(rw http.ResponseWriter, req *http.Request) {
	var doc saveDocReq

	if err := json.NewDecoder(req.Body).Decode(&doc.Request); err != nil {
		o.writeErrorResponse(rw, err, http.StatusBadRequest)

		return
	}

	var (
		vaultID    = mux.Vars(req)["vaultID"]
		docID      = doc.Request.ID
		docContent = doc.Request.Content
	)

	if docID == "" {
		var err error

		docID, err = o.GenerateID()
		if err != nil {
			o.writeErrorResponse(rw, err, http.StatusInternalServerError)

			return
		}
	}

	result, err := o.vault.SaveDoc(vaultID, docID, docContent)
	if err != nil {
		o.writeErrorResponse(rw, err, http.StatusInternalServerError)

		return
	}

	var resp saveDocResp
	resp.Body = result

	o.WriteResponse(rw, resp.Body, http.StatusCreated)
}

// GetDocMetadata swagger:route GET /vaults/{vaultID}/docs/{docID}/metadata vault getDocMetadataReq
//
// Returns the document`s metadata by given docID.
//
// Responses:
//    default: genericError
//        200: getDocMetadataResp
func (o *Operation) GetDocMetadata(rw http.ResponseWriter, req *http.Request) {
	var (
		vaultID = mux.Vars(req)["vaultID"]
		docID   = mux.Vars(req)["docID"]
	)

	result, err := o.vault.GetDocMetadata(vaultID, docID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.HasSuffix(err.Error(), messages.ErrDocumentNotFound.Error()+".") {
			status = http.StatusNotFound
		}

		o.writeErrorResponse(rw, err, status)

		return
	}

	var resp getDocMetadataResp
	resp.Body = result

	o.WriteResponse(rw, resp.Body, http.StatusOK)
}

// CreateAuthorization swagger:route POST /vaults/{vaultID}/authorizations vault createAuthorizationsReq
//
// Creates an authorization.
//
// Responses:
//    default: genericError
//        201: createAuthorizationResp
func (o *Operation) CreateAuthorization(rw http.ResponseWriter, req *http.Request) {
	var doc createAuthorizationsReq

	if err := json.NewDecoder(req.Body).Decode(&doc.Request); err != nil {
		o.writeErrorResponse(rw, err, http.StatusBadRequest)

		return
	}

	var (
		vaultID         = mux.Vars(req)["vaultID"]
		scope           = doc.Request.Scope
		requestingParty = doc.Request.RequestingParty
	)

	result, err := o.vault.CreateAuthorization(vaultID, requestingParty, &scope)
	if err != nil {
		o.writeErrorResponse(rw, err, http.StatusInternalServerError)

		return
	}

	var resp createAuthorizationResp
	resp.Body = result

	o.WriteResponse(rw, resp.Body, http.StatusCreated)
}

// GetAuthorization swagger:route GET /vaults/{vaultID}/authorizations/{authID} vault getAuthorizationReq
//
// Fetches an authorization.
//
// Responses:
//    default: genericError
//        200: getAuthorizationResp
func (o *Operation) GetAuthorization(rw http.ResponseWriter, req *http.Request) {
	var (
		vaultID = mux.Vars(req)["vaultID"]
		authID  = mux.Vars(req)["authID"]
	)

	result, err := o.vault.GetAuthorization(vaultID, authID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrDataNotFound) {
			status = http.StatusNotFound
		}

		o.writeErrorResponse(rw, err, status)

		return
	}

	var resp createAuthorizationResp
	resp.Body = result

	o.WriteResponse(rw, resp.Body, http.StatusOK)
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

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, err error, status int) {
	logger.Errorf("%v", err)

	o.WriteResponse(rw, model.ErrorResponse{
		Message: fmt.Sprintf("%v", err),
	}, status)
}

// WriteResponse writes response.
func (o *Operation) WriteResponse(rw http.ResponseWriter, v interface{}, status int) {
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("unable to send a response: %v", err)
	}
}
