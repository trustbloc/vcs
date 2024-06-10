/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

// WalletIssuanceRequest is a request model for wallet issuance policy evaluation.
type WalletIssuanceRequest struct {
	IssuerDID        string            `json:"issuer_did"`
	IssuerDomain     string            `json:"issuer_domain,omitempty"`
	CredentialOffers []CredentialOffer `json:"credential_offers"`
}

// CredentialOffer contains the data for a credential in a wallet issuance request.
type CredentialOffer struct {
	ClientAttestationRequested bool   `json:"client_attestation_requested,omitempty"`
	CredentialFormat           string `json:"credential_format,omitempty"`
	CredentialType             string `json:"credential_type,omitempty"`
}

type CredentialMatch struct {
	CredentialID        string                 `json:"credential_id,omitempty"`
	CredentialTypes     []string               `json:"credential_types,omitempty"`
	ExpirationDate      string                 `json:"expiration_date,omitempty"`
	IssuanceDate        string                 `json:"issuance_date,omitempty"`
	IssuerID            string                 `json:"issuer_id,omitempty"`
	CredentialClaimKeys map[string]interface{} `json:"credential_claim_keys,omitempty"`
	CredentialFormat    string                 `json:"credential_format,omitempty"`
}

// WalletPresentationRequest is a request model for wallet presentation policy evaluation.
type WalletPresentationRequest struct {
	CredentialMatches []CredentialMatch `json:"credential_matches"`
	VerifierDID       string            `json:"verifier_did"`
	VerifierDomain    string            `json:"verifier_domain,omitempty"`
}

type PolicyEvaluationResponse struct {
	Allowed     bool                    `json:"allowed"`
	DenyReasons *[]string               `json:"deny_reasons,omitempty"`
	Payload     *map[string]interface{} `json:"payload,omitempty"`
}
