/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

// VerifierPresentationValidationConfig represents DTO for verifier presentation policy evaluation.
type VerifierPresentationValidationConfig struct {
	// Attestation verifiable credential(s).
	AttestationVC []string `json:"attestation_vc"`
	// Verifier DID.
	VerifierDID string `json:"verifier_did"`
	// Credential metadata for Requested VCs only.
	RequestedVCMetadata []*CredentialMetadata `json:"credential_metadata"`
}

type WalletPresentationValidationConfig struct {
	VerifierDID         string                `json:"verifier_did"`
	RequestedVCMetadata []*CredentialMetadata `json:"credential_metadata"`
}

type CredentialMetadata struct {
	// Credential ID
	CredentialID string `json:"credential_id"`
	// Credential Types.
	Types []string `json:"credential_types"`
	// Issuer ID.
	IssuerID string `json:"issuer_id"`
	// Issuance date/time.
	Issued string `json:"issuance_date"`
	// Expiration date/time.
	Expired string `json:"expiration_date"`
}
