/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

// WalletIssuanceRequest is a request model for wallet issuance policy evaluation.
type WalletIssuanceRequest struct {
	ClientAttestationRequested bool   `json:"client_attestation_requested,omitempty"`
	CredentialFormat           string `json:"credential_format,omitempty"`
	CredentialType             string `json:"credential_type,omitempty"`
	IssuerDID                  string `json:"issuer_did"`
	IssuerDomain               string `json:"issuer_domain,omitempty"`
}

type CredentialMetadata struct {
	CredentialID    string   `json:"credential_id,omitempty"`
	CredentialTypes []string `json:"credential_types,omitempty"`
	ExpirationDate  string   `json:"expiration_date,omitempty"`
	IssuanceDate    string   `json:"issuance_date,omitempty"`
	IssuerID        string   `json:"issuer_id,omitempty"`
}

// WalletPresentationRequest is a request model for wallet presentation policy evaluation.
type WalletPresentationRequest struct {
	CredentialMetadata []CredentialMetadata `json:"credential_metadata"`
	VerifierDID        string               `json:"verifier_did"`
	VerifierDomain     string               `json:"verifier_domain,omitempty"`
}

type PolicyEvaluationResponse struct {
	Allowed bool                    `json:"allowed"`
	Payload *map[string]interface{} `json:"payload,omitempty"`
}
