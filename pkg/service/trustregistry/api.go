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

// CredentialMetadata represents metadata of matched credentials for policy evaluation.
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

// IssuancePolicyEvaluationRequest is a request payload for issuance policy evaluation service.
type IssuancePolicyEvaluationRequest struct {
	CredentialTypes []string  `json:"credential_types"`
	AttestationVC   *[]string `json:"attestation_vc,omitempty"`
	IssuerDID       string    `json:"issuer_did"`
}

// PresentationPolicyEvaluationRequest is a request payload for presentation policy evaluation service.
type PresentationPolicyEvaluationRequest struct {
	AttestationVC      *[]string            `json:"attestation_vc,omitempty"`
	CredentialMetadata []CredentialMetadata `json:"credential_metadata"`
	VerifierDID        string               `json:"verifier_did"`
}

// PolicyEvaluationResponse is a response from policy evaluation service.
type PolicyEvaluationResponse struct {
	Allowed bool                   `json:"allowed"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// ServiceInterface defines an interface for client attestation service. The task of service is to validate and confirm
// the device binding and authentication of the client instance by validating attestation VP and evaluating policy.
type ServiceInterface interface {
	ValidateIssuance(ctx context.Context, profile *profileapi.Issuer, jwtVP string) error
	ValidatePresentation(ctx context.Context, profile *profileapi.Verifier, jwtVP string) error
}
