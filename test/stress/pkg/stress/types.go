/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package stress

import "time"

type Result struct {
	UserCount          int                           `json:"user_count"`
	ConcurrentRequests int                           `json:"concurrent_requests"`
	Metrics            []*Metric                     `json:"metrics"`
	TotalDuration      time.Duration                 `json:"total_duration"`
	Errors             []error                       `json:"-"`
	PerCredentialData  map[string]*PerCredentialData `json:"per_credential_data"`
}

type Metric struct {
	Name string
	Avg  time.Duration
	Max  time.Duration
	Min  time.Duration
}

type initiateOIDC4CIResponse struct {
	OfferCredentialURL string  `json:"offer_credential_url"`
	TxId               string  `json:"tx_id"`
	UserPin            *string `json:"user_pin"`
}

type initiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxID                 string `json:"txID"`
}

type PerCredentialData struct {
	Metrics map[string]string `json:"metrics"`
	Error   string            `json:"error"`
}

// initiateOIDC4VPData defines model for InitiateOIDC4VPData.
type initiateOIDC4VPData struct {
	PresentationDefinitionId *string `json:"presentationDefinitionId,omitempty"`
}

type WalletConfiguration struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Type            string `json:"type"`
	Compliance      string `json:"compliance"`
	AttestationType string `json:"attestation_type"`
}

type Urls struct {
	TrustRegistryHost     string `json:"trust_registry_host"`
	AttestationServiceURL string `json:"attestation_service_url"`
}
