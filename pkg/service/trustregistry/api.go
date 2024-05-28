/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

import (
	"context"
	"errors"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var ErrInteractionRestricted = errors.New("interaction restricted")

// ValidateIssuance requests evaluation of the given policy to validate that the wallet has satisfied attestation
// requirements.
type ValidateIssuance interface {
	ValidateIssuance(ctx context.Context, profile *profileapi.Issuer, data *ValidateIssuanceData) error
}

type ValidateIssuanceData struct {
	AttestationVP   string
	CredentialTypes []string
	Nonce           string
}

// ValidatePresentation requests evaluation of the given policy to validate that the presented credential is presented
// as per policy (by type, by issuer DID, etc.).
type ValidatePresentation interface {
	ValidatePresentation(ctx context.Context, profile *profileapi.Verifier, data *ValidatePresentationData) error
}

type ValidatePresentationData struct {
	AttestationVP     string
	CredentialMatches []CredentialMatches
}

// ServiceInterface defines an interface for Trust Registry service.
type ServiceInterface interface {
	ValidateIssuance
	ValidatePresentation
}

// CredentialMatches represents metadata of matched credentials for policy evaluation.
type CredentialMatches struct {
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

// IssuancePolicyEvaluationRequest is a request payload for issuance policy evaluation service.
type IssuancePolicyEvaluationRequest struct {
	CredentialTypes []string  `json:"credential_types"`
	AttestationVC   *[]string `json:"attestation_vc,omitempty"`
	IssuerDID       string    `json:"issuer_did"`
}

// PresentationPolicyEvaluationRequest is a request payload for presentation policy evaluation service.
type PresentationPolicyEvaluationRequest struct {
	AttestationVC     *[]string           `json:"attestation_vc,omitempty"`
	CredentialMatches []CredentialMatches `json:"credential_matches"`
	VerifierDID       string              `json:"verifier_did"`
}

// PolicyEvaluationResponse is a response from policy evaluation service.
type PolicyEvaluationResponse struct {
	Allowed     bool                   `json:"allowed"`
	DenyReasons *[]string              `json:"deny_reasons,omitempty"`
	Payload     map[string]interface{} `json:"payload,omitempty"`
}
