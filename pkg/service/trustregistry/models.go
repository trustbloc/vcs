/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

type VerifierValidationConfig struct {
	VerifierDID string                `json:"verifier_did"`
	Metadata    []*CredentialMetadata `json:"metadata"`
}

type PresentationValidationConfig struct {
	PolicyID      string                `json:"policy_id"`
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

type Response struct {
	Allowed bool `json:"allowed"`
}
