/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

type WalletPresentationValidationConfig struct {
	VerifierDID string                `json:"verifier_did"`
	Metadata    []*CredentialMetadata `json:"credential_metadata"`
}

// CredentialMetadata defines model for CredentialMetadata.
type CredentialMetadata struct {
	// Credential ID
	CredentialID string `json:"credential_id,omitempty"`

	// Credential Types
	CredentialTypes []string `json:"credential_types,omitempty"`

	// Expiration date/time.
	ExpirationDate string `json:"expiration_date,omitempty"`

	// Issuance date/time.
	IssuanceDate string `json:"issuance_date,omitempty"`

	// Issuer ID
	IssuerID string `json:"issuer_id,omitempty"`
}

type Response struct {
	Allowed bool `json:"allowed"`
}
