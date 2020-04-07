/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"time"

	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
)

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	ErrorResponse
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

// issuerProfileRes model
//
// swagger:response issuerProfileRes
type issuerProfileRes struct { // nolint: unused,deadcode
	// in: body
	dataProfile
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

// DataProfile struct for profile
type dataProfile struct { // nolint: unused
	Name                    string     `json:"name,omitempty"`
	DID                     string     `json:"did,omitempty"`
	URI                     string     `json:"uri,omitempty"`
	SignatureType           string     `json:"signatureType,omitempty"`
	SignatureRepresentation int        `json:"signatureRepresentation,omitempty"`
	Creator                 string     `json:"creator,omitempty"`
	Created                 *time.Time `json:"created,omitempty"`
	DIDPrivateKey           string     `json:"didPrivateKey,omitempty"`
}

// verifyCredentialReq model
//
// swagger:parameters verifyCredentialReq
type verifyCredentialReq struct { // nolint: unused,deadcode
	// in: body
	Params CredentialsVerificationRequest
}

// verifyCredentialSuccessResp model
//
// swagger:response verifyCredentialSuccessResp
type verifyCredentialSuccessResp struct { // nolint: unused,deadcode
	// in: body
	CredentialsVerificationSuccessResponse
}

// verifyCredentialFailureResp model
//
// swagger:response verifyCredentialFailureResp
type verifyCredentialFailureResp struct { // nolint: unused,deadcode
	// in: body
	Checks []*CredentialsVerificationCheckResult `json:"checks,omitempty"`
}

// verifyCredentialReq model
//
// swagger:parameters verifyPresentationReq
type verifyPresentationReq struct { // nolint: unused,deadcode
	// in: body
	Params VerifyPresentationRequest
}

// verifyPresentationSuccessResp model
//
// swagger:response verifyPresentationSuccessResp
type verifyPresentationSuccessResp struct { // nolint: unused,deadcode
	// in: body
	VerifyPresentationSuccessResponse
}

// verifyPresentationFailureResp model
//
// swagger:response verifyPresentationFailureResp
type verifyPresentationFailureResp struct { // nolint: unused,deadcode
	// in: body
	Checks []*VerifyPresentationCheckResult `json:"checks,omitempty"`
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
	cslstatus.CSL
}
