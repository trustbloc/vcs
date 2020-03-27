/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CreateCredentialRequest input data for edge service issuer rest api
type CreateCredentialRequest struct {
	Context []string           `json:"@context,omitempty"`
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
	Profile string             `json:"profile,omitempty"`
}

// UpdateCredentialStatusRequest request struct for updating vc status
type UpdateCredentialStatusRequest struct {
	Credential   string `json:"credential"`
	Status       string `json:"status"`
	StatusReason string `json:"statusReason"`
}

// StoreVCRequest stores the credential with profile name
type StoreVCRequest struct {
	Profile    string `json:"profile"`
	Credential string `json:"credential"`
}

// ProfileRequest struct the input for creating profile
type ProfileRequest struct {
	Name                    string                             `json:"name"`
	URI                     string                             `json:"uri"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	DID                     string                             `json:"did"`
	DIDPrivateKey           string                             `json:"didPrivateKey"`
}

// VerifyCredentialResponse describes verify credential response
type VerifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

// IssueCredentialRequest request for issuing credential.
type IssueCredentialRequest struct {
	Credential json.RawMessage        `json:"credential,omitempty"`
	Opts       IssueCredentialOptions `json:"options,omitempty"`
}

// IssueCredentialOptions options for issuing credential.
type IssueCredentialOptions struct {
	AssertionMethod string `json:"assertionMethod,omitempty"`
}

// ComposeCredentialRequest for composing and issuing credential.
type ComposeCredentialRequest struct {
	Issuer                  string          `json:"issuer,omitempty"`
	Subject                 string          `json:"subject,omitempty"`
	Types                   []string        `json:"types,omitempty"`
	IssuanceDate            *time.Time      `json:"issuanceDate,omitempty"`
	ExpirationDate          *time.Time      `json:"expirationDate,omitempty"`
	Claims                  json.RawMessage `json:"claims,omitempty"`
	Evidence                json.RawMessage `json:"evidence,omitempty"`
	TermsOfUse              json.RawMessage `json:"termsOfUse,omitempty"`
	CredentialFormat        string          `json:"credentialFormat,omitempty"`
	ProofFormat             string          `json:"proofFormat,omitempty"`
	CredentialFormatOptions json.RawMessage `json:"credentialFormatOptions,omitempty"`
	ProofFormatOptions      json.RawMessage `json:"proofFormatOptions,omitempty"`
}

// GenerateKeyPairResponse contains response from KMS generate keypair API.
type GenerateKeyPairResponse struct {
	PublicKey string `json:"publicKey,omitempty"`
}

// CredentialsVerificationRequest request for verifying credential.
type CredentialsVerificationRequest struct {
	Credential json.RawMessage                 `json:"credential,omitempty"`
	Opts       *CredentialsVerificationOptions `json:"options,omitempty"`
}

// CredentialsVerificationOptions options for credential verifications.
type CredentialsVerificationOptions struct {
	Checks []string `json:"checks,omitempty"`
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
