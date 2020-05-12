/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

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
