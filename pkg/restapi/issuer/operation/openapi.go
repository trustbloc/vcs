/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	model.ErrorResponse
}

// issuerProfileReq model
//
// swagger:parameters issuerProfileReq
type issuerProfileReq struct { // nolint: unused,deadcode
	// in: body
	Params ProfileRequest
}

// retrieveProfileReq model
//
// swagger:parameters retrieveProfileReq
type retrieveProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// deleteIssuerProfileReq model
//
// swagger:parameters deleteIssuerProfileReq
type deleteIssuerProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// issuerProfileRes model
//
// swagger:response issuerProfileRes
type issuerProfileRes struct { // nolint: unused,deadcode
	// in: body
	model.DataProfile
}

// issueCredentialReq model
//
// swagger:parameters issueCredentialReq
type issueCredentialReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Params IssueCredentialRequest
}

// issueCredentialReq model for OpenAPI annotation
//
// swagger:parameters composeCredentialReq
type composeCredentialReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Params ComposeCredentialRequest
}

// verifiableCredentialRes model contains the verifiable credential
//
// swagger:response verifiableCredentialRes
type verifiableCredentialRes struct { // nolint: unused,deadcode
	// in: body
}

// generateKeypairResp model
//
// swagger:response generateKeypairResp
type generateKeypairResp struct { // nolint: unused,deadcode
	// in: body
	GenerateKeyPairResponse
}

// storeCredentialReq model
//
// swagger:parameters storeCredentialReq
type storeCredentialReq struct { // nolint: unused,deadcode
	// in: body
	Params StoreVCRequest
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { // nolint: unused,deadcode
}

// retrieveCredentialReq model
//
// swagger:parameters retrieveCredentialReq
type retrieveCredentialReq struct { // nolint: unused,deadcode
	// credential id
	//
	// in: query
	// required: true
	ID string `json:"id"`

	// profile
	//
	// in: query
	// required: true
	Profile string `json:"profile"`
}

// updateCredentialStatusReq model
//
// swagger:parameters updateCredentialStatusReq
type updateCredentialStatusReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Params UpdateCredentialStatusRequest
}

// retrieveCredentialStatusReq model
//
// swagger:parameters retrieveCredentialStatusReq
type retrieveCredentialStatusReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// retrieveCredentialStatusResp model
//
// swagger:response retrieveCredentialStatusResp
type retrieveCredentialStatusResp struct { // nolint: unused,deadcode
	// in: body
}
