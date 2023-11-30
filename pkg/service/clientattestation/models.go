/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation

type IssuerInteractionValidationConfig struct {
	AttestationVC interface{}           `json:"attestation_vc"`
	Metadata      []*CredentialMetadata `json:"metadata"`
}

// VerifierPresentationValidationConfig represents DTO for verifier presentation policy evaluation.
type VerifierPresentationValidationConfig struct {
	// Attestation verifiable credential(s).
	AttestationVC []string `json:"attestation_vc"`
	// Verifier DID.
	VerifierDID string `json:"verifier_did"`
	// Credential metadata for Requested VCs only.
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

type TrustRegistryResponse struct {
	Allowed bool `json:"allowed"`
}
