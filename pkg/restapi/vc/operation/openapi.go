/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"time"
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
	Params issueCredentialRequest
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
	Params composeCredentialRequest
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

// issueCredentialRequest request for issuing credential. Added a new struct definition as OpenAPI
// shows json.RawMessage as array in the specification instead of object.
type issueCredentialRequest struct { // nolint: unused
	Credential interface{}             `json:"credential,omitempty"`
	Opts       *IssueCredentialOptions `json:"options,omitempty"`
}

// ComposeCredentialRequest for composing and issuing credential. Added a new struct definition as OpenAPI
// shows json.RawMessage as array in the specification instead of object.
type composeCredentialRequest struct { // nolint: unused
	Issuer                  string      `json:"issuer,omitempty"`
	Subject                 string      `json:"subject,omitempty"`
	Types                   []string    `json:"types,omitempty"`
	IssuanceDate            *time.Time  `json:"issuanceDate,omitempty"`
	ExpirationDate          *time.Time  `json:"expirationDate,omitempty"`
	Claims                  interface{} `json:"claims,omitempty"`
	Evidence                interface{} `json:"evidence,omitempty"`
	TermsOfUse              interface{} `json:"termsOfUse,omitempty"`
	CredentialFormat        string      `json:"credentialFormat,omitempty"`
	ProofFormat             string      `json:"proofFormat,omitempty"`
	CredentialFormatOptions interface{} `json:"credentialFormatOptions,omitempty"`
	ProofFormatOptions      interface{} `json:"proofFormatOptions,omitempty"`
}

// verifyCredentialReq model
//
// swagger:parameters verifyCredentialReq
type verifyCredentialReq struct { // nolint: unused,deadcode
	// in: body
	Params verifyCredentialRequest
}

// verifyCredentialRequest request for verifying credential.
type verifyCredentialRequest struct { // nolint: unused
	Credential interface{}                     `json:"verifiableCredential,omitempty"`
	Opts       *CredentialsVerificationOptions `json:"options,omitempty"`
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
	Params verifyPresentationRequest
}

// verifyCredentialRequest request for verifying credential.
type verifyPresentationRequest struct { // nolint: unused
	Presentation interface{}                `json:"verifiablePresentation,omitempty"`
	Opts         *VerifyPresentationOptions `json:"options,omitempty"`
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
