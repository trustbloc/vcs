/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/vcs/pkg/restapi/model"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"
)

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	model.ErrorResponse
}

// profileData model
//
// swagger:response profileData
type profileData struct { // nolint: unused,deadcode
	// in: body
	vcsstorage.VerifierProfile
}

// getProfileReq model
//
// swagger:parameters getProfileReq
type getProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// deleteProfileReq model
//
// swagger:parameters deleteProfileReq
type deleteProfileReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// verifyCredentialReq model
//
// swagger:parameters verifyCredentialReq
type verifyCredentialReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

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

// verifyPresentationReq model
//
// swagger:parameters verifyPresentationReq
type verifyPresentationReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

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

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { // nolint: unused,deadcode
}
