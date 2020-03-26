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
	Issuer                  string              `json:"issuer,omitempty"`
	Subject                 string              `json:"subject,omitempty"`
	Types                   []string            `json:"types,omitempty"`
	IssuanceDate            *time.Time          `json:"issuanceDate,omitempty"`
	ExpirationDate          *time.Time          `json:"expirationDate,omitempty"`
	Claims                  json.RawMessage     `json:"claims,omitempty"`
	Evidence                verifiable.Evidence `json:"evidence,omitempty"`
	TermsOfUse              json.RawMessage     `json:"termsOfUse,omitempty"`
	CredentialFormat        string              `json:"credentialFormat,omitempty"`
	ProofFormat             string              `json:"proofFormat,omitempty"`
	CredentialFormatOptions json.RawMessage     `json:"credentialFormatOptions,omitempty"`
	ProofFormatOptions      json.RawMessage     `json:"proofFormatOptions,omitempty"`
}

// GenerateKeyPairResponse contains response from KMS generate keypair API.
type GenerateKeyPairResponse struct {
	PublicKey string `json:"publicKey,omitempty"`
}

// CredentialVerificationsRequest request for issuing credential.
type CredentialVerificationsRequest struct {
	Credential json.RawMessage                 `json:"credential,omitempty"`
	Opts       *CredentialVerificationsOptions `json:"options,omitempty"`
}

// CredentialVerificationsOptions options for credential verifications.
type CredentialVerificationsOptions struct {
	Checks []string `json:"checks,omitempty"`
}

// CredentialVerificationsSuccessResponse resp when credential verification is success.
type CredentialVerificationsSuccessResponse struct {
	Checks []string `json:"checks,omitempty"`
}

// CredentialVerificationsFailResponse resp when credential verification is failed.
type CredentialVerificationsFailResponse struct {
	Checks []CredentialVerificationsCheckResult `json:"checks,omitempty"`
}

// CredentialVerificationsCheckResult resp containing failure check details.
type CredentialVerificationsCheckResult struct {
	Check              string `json:"check,omitempty"`
	Error              string `json:"error,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
}
