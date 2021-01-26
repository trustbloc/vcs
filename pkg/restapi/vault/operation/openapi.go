/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	Body http.ErrorResponse
}

// createVaultReq model
//
// swagger:parameters createVaultReq
type createVaultReq struct{} // nolint: unused,deadcode

// createVaultResp model
//
// swagger:response createVaultResp
type createVaultResp struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		ID  string   `json:"id"`
		EDV location `json:"edv"`
		KMS location `json:"kms"`
	}
}

type location struct { // nolint: unused
	URI  string      `json:"uri"`
	ZCap interface{} `json:"zcap"`
}

// saveDocReq model
//
// swagger:parameters saveDocReq
type saveDocReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: body
	// required: true
	Request doc
}

// saveDocResp model
//
// swagger:response saveDocResp
type saveDocResp struct { // nolint: unused,deadcode
	// in: body
	Body doc
}

// getDocReq model
//
// swagger:parameters getDocReq
type getDocReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: path
	DocID string `json:"docID"`
}

// getDocResp model
//
// swagger:response getDocResp
type getDocResp struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// createAuthorizationReq model
//
// swagger:parameters createAuthorizationReq
type createAuthorizationReq struct { // nolint: unused,deadcode
	// in: path
	VaultID string `json:"vaultID"`
	// in: body
	// required: true
	Request authorization
}

// createAuthorizationResp model
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct { // nolint: unused,deadcode
	// in: body
	Body authorization
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
	Body authorization
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

type authorization struct { // nolint: unused
	ID    string `json:"id"`
	Scope struct {
		Target     string   `json:"target"`
		TargetAttr string   `json:"targetAttr"`
		Actions    []string `json:"actions"`
		Caveats    []struct {
			Type string `json:"type"`
		} `json:"caveats"`
	} `json:"scope"`
	RequestingParty string   `json:"requestingParty"`
	EDV             location `json:"edv"`
	KMS             location `json:"kms"`
}

type doc struct { // nolint: unused
	ID        string      `json:"id"`
	Content   interface{} `json:"content"`
	Tags      []string    `json:"tags"`
	EDVDocURI string      `json:"edvDocURI"`
}
