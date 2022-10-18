/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

type initiateOIDC4VCRequest struct {
	ClaimEndpoint             string   `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceUrl string   `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string   `json:"client_wellknown,omitempty"`
	CredentialTemplateId      string   `json:"credential_template_id,omitempty"`
	GrantType                 string   `json:"grant_type,omitempty"`
	OpState                   string   `json:"op_state,omitempty"`
	ResponseType              string   `json:"response_type,omitempty"`
	Scope                     []string `json:"scope,omitempty"`
}

type initiateOIDC4VCResponse struct {
	InitiateIssuanceUrl string `json:"initiate_issuance_url"`
	TxId                string `json:"tx_id"`
}
