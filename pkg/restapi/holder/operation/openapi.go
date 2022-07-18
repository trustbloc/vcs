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

// holderProfileRes model
//
// swagger:response holderProfileRes
type holderProfileRes struct { // nolint: unused,deadcode
	// in: body
	model.DataProfile
}

// retrieveHolderProfileReq model
//
// swagger:parameters retrieveHolderProfileReq
type retrieveHolderProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// holderProfileReq model
//
// swagger:parameters holderProfileReq
type holderProfileReq struct { // nolint: unused,deadcode
	// in: body
	Params HolderProfileRequest
}

// deleteHolderProfileReq model
//
// swagger:parameters deleteHolderProfileReq
type deleteHolderProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// signPresentationReq model
//
// swagger:parameters signPresentationReq
type signPresentationReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Params SignPresentationRequest
}

// signPresentationRes model
//
// swagger:response signPresentationRes
type signPresentationRes struct { // nolint: unused,deadcode
	// in: body
}

// verifiableCredentialRes model
//
// swagger:response verifiableCredentialRes
type verifiableCredentialRes struct { // nolint: unused,deadcode
	// in: body
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { // nolint: unused,deadcode
}

// deriveCredentialReq model
//
// This is used for deriving a credential.
//
// swagger:parameters deriveCredentialReq
type deriveCredentialReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Body DeriveCredentialRequest
}

// deriveCredentialRes model
//
// This is used for returning the derive credential response.
//
// swagger:response deriveCredentialRes
type deriveCredentialRes struct { // nolint: unused,deadcode
	// in: body
	Body DeriveCredentialResponse
}
