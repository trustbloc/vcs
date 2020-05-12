/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "encoding/json"

// CredentialsVerificationRequest request for verifying credential.
type CredentialsVerificationRequest struct {
	Credential json.RawMessage                 `json:"verifiableCredential,omitempty"`
	Opts       *CredentialsVerificationOptions `json:"options,omitempty"`
}

// CredentialsVerificationOptions options for credential verifications.
type CredentialsVerificationOptions struct {
	Domain    string   `json:"domain,omitempty"`
	Challenge string   `json:"challenge,omitempty"`
	Checks    []string `json:"checks,omitempty"`
}

// CredentialsVerificationSuccessResponse resp when credential verification is success.
type CredentialsVerificationSuccessResponse struct {
	Checks []string `json:"checks,omitempty"`
}

// CredentialsVerificationFailResponse resp when credential verification is failed.
type CredentialsVerificationFailResponse struct {
	Checks []CredentialsVerificationCheckResult `json:"checks,omitempty"`
}

// CredentialsVerificationCheckResult resp containing failure check details.
type CredentialsVerificationCheckResult struct {
	Check              string `json:"check,omitempty"`
	Error              string `json:"error,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
}

// VerifyPresentationRequest request for verifying presentation.
type VerifyPresentationRequest struct {
	Presentation json.RawMessage            `json:"verifiablePresentation,omitempty"`
	Opts         *VerifyPresentationOptions `json:"options,omitempty"`
}

// VerifyPresentationOptions options for presentation verifications.
type VerifyPresentationOptions struct {
	Domain    string   `json:"domain,omitempty"`
	Challenge string   `json:"challenge,omitempty"`
	Checks    []string `json:"checks,omitempty"`
}

// VerifyPresentationSuccessResponse resp when presentation verification is success.
type VerifyPresentationSuccessResponse struct {
	Checks []string `json:"checks,omitempty"`
}

// VerifyPresentationFailureResponse resp when presentation verification is failed.
type VerifyPresentationFailureResponse struct {
	Checks []VerifyPresentationCheckResult `json:"checks,omitempty"`
}

// VerifyPresentationCheckResult resp containing failure check details.
type VerifyPresentationCheckResult struct {
	Check              string `json:"check,omitempty"`
	Error              string `json:"error,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
}

// VerifyCredentialResponse describes verify credential response
type VerifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}
