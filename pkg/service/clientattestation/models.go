/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation

type IssuerInteractionValidationConfig struct {
	AttestationVC interface{}           `json:"attestation_vc"`
	Metadata      []*CredentialMetadata `json:"metadata"`
}

type VerifierInteractionValidationConfig struct {
	AttestationVC interface{}           `json:"attestation_vc"`
	Metadata      []*CredentialMetadata `json:"metadata"`
}

type CredentialMetadata struct {
	CredentialID string   `json:"credential_id"`
	Types        []string `json:"types"`
	Issuer       string   `json:"issuer"`
	Issued       string   `json:"issued"`
	Expired      string   `json:"expired"`
}

type TrustRegistryResponse struct {
	Allowed bool `json:"allowed"`
}
