/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

type verifierProfile struct {
	Active         bool                   `json:"active,omitempty"`
	Checks         *verifierChecks        `json:"checks,omitempty"`
	ID             string                 `json:"id,omitempty"`
	Name           string                 `json:"name,omitempty"`
	OIDCConfig     map[string]interface{} `json:"oidcConfig,omitempty"`
	OrganizationID string                 `json:"organizationID,omitempty"`
	URL            string                 `json:"url,omitempty"`
}

type verifierChecks struct {
	Credential   *credentialCheck   `json:"credential,omitempty"`
	Presentation *presentationCheck `json:"presentation,omitempty"`
}

type credentialCheck struct {
	Format []string `json:"format,omitempty"`
	Proof  bool     `json:"proof,omitempty"`
	Status bool     `json:"status,omitempty"`
}

type presentationCheck struct {
	Format []string `json:"format,omitempty"`
	Proof  bool     `json:"proof,omitempty"`
}
