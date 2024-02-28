/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

// WalletIssuanceRequest is a model for wallet issuance policy evaluation.
type WalletIssuanceRequest struct {
	CredentialOffers *[]CredentialOffer `json:"credential_offers,omitempty"`
	IssuerDID        string             `json:"issuer_did"`
	IssuerDomain     *string            `json:"issuer_domain,omitempty"`
}

// CredentialOffer is a model for CredentialOffer.
type CredentialOffer struct {
	ClientAttestationRequested *bool   `json:"client_attestation_requested,omitempty"`
	CredentialFormat           *string `json:"credential_format,omitempty"`
	CredentialType             *string `json:"credential_type,omitempty"`
}

// WalletPresentationRequest is a model for wallet presentation policy evaluation.
type WalletPresentationRequest struct {
	CredentialMetadata []CredentialMetadata `json:"credential_metadata"`
	VerifierDID        string               `json:"verifier_did"`
	VerifierDomain     *string              `json:"verifier_domain,omitempty"`
}

// IssuerIssuanceRequest is a model for issuer issuance policy evaluation.
type IssuerIssuanceRequest struct {
	AttestationVC   *[]string `json:"attestation_vc,omitempty"`
	CredentialTypes []string  `json:"credential_types"`
	IssuerDID       string    `json:"issuer_did"`
}

// VerifierPresentationRequest is a model for verifier presentation policy evaluation.
type VerifierPresentationRequest struct {
	AttestationVC      *[]string            `json:"attestation_vc,omitempty"`
	CredentialMetadata []CredentialMetadata `json:"credential_metadata"`
	VerifierDID        string               `json:"verifier_did"`
}

// CredentialMetadata defines model for CredentialMetadata.
type CredentialMetadata struct {
	CredentialID    *string   `json:"credential_id,omitempty"`
	CredentialTypes *[]string `json:"credential_types,omitempty"`
	ExpirationDate  *string   `json:"expiration_date,omitempty"`
	IssuanceDate    *string   `json:"issuance_date,omitempty"`
	IssuerID        *string   `json:"issuer_id,omitempty"`
}

// PolicyEvaluationResponse defines model for PolicyEvaluationResponse.
type PolicyEvaluationResponse struct {
	Allowed bool                    `json:"allowed"`
	Payload *map[string]interface{} `json:"payload,omitempty"`
}
