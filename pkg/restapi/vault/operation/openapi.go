/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	Body model.ErrorResponse
}

// createVaultReq model
//
// swagger:parameters createVaultReq
type createVaultReq struct{} // nolint: unused,deadcode

// createVaultResp model
//
// swagger:response createVaultResp
type createVaultResp struct {
	// in: body
	Body *vault.CreatedVault
}

// saveDocReq model
//
// swagger:parameters saveDocReq
type saveDocReq struct {
	// in: path
	VaultID string `json:"vaultID"`
	// in: body
	// required: true
	Request SaveDocRequestBody
}

// SaveDocRequestBody describes body for the SaveDoc request.
type SaveDocRequestBody struct {
	ID      string      `json:"id"`
	Content interface{} `json:"content"`
	Tags    []string    `json:"tags"`
}

// saveDocResp model
//
// swagger:response saveDocResp
type saveDocResp struct {
	// in: body
	Body *vault.DocumentMetadata
}

// getDocMetadataReq model
//
// swagger:parameters getDocMetadataReq
type getDocMetadataReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: path
	DocID string `json:"docID"`
}

// getDocMetadataResp model
//
// swagger:response getDocMetadataResp
type getDocMetadataResp struct {
	// in: body
	Body *vault.DocumentMetadata
}

// createAuthorizationsReq model
//
// swagger:parameters createAuthorizationsReq
type createAuthorizationsReq struct {
	// in: path
	VaultID string `json:"vaultID"`
	// in: body
	// required: true
	Request CreateAuthorizationsBody
}

// CreateAuthorizationsBody describes body for the createAuthorizations request.
type CreateAuthorizationsBody struct {
	Scope           vault.AuthorizationsScope `json:"scope"`
	RequestingParty string                    `json:"requestingParty"`
}

// createAuthorizationResp model
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct {
	// in: body
	Body *vault.CreatedAuthorization
}

// getAuthorizationReq model
//
// swagger:parameters getAuthorizationReq
type getAuthorizationReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: path
	AuthorizationID string `json:"authID"`
}

// getAuthorizationResp model
//
// swagger:response getAuthorizationResp
type getAuthorizationResp struct { // nolint: unused,deadcode
	// in: body
	Body *vault.CreatedAuthorization
}

// deleteAuthorizationReq model
//
// swagger:parameters deleteAuthorizationReq
type deleteAuthorizationReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: path
	AuthorizationID string `json:"authID"`
}

// deleteAuthorizationResp model
//
// swagger:response deleteAuthorizationResp
type deleteAuthorizationResp struct{} // nolint: unused,deadcode

// deleteVaultReq model
//
// swagger:parameters deleteVaultReq
type deleteVaultReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
}

// deleteVaultResp model
//
// swagger:response deleteVaultResp
type deleteVaultResp struct{} // nolint: unused,deadcode
