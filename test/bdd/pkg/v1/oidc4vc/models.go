/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

type initiateOIDC4VCRequest struct {
	ClaimData                 *map[string]interface{} `json:"claim_data,omitempty"`
	ClaimEndpoint             string                  `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceUrl string                  `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string                  `json:"client_wellknown,omitempty"`
	CredentialTemplateId      string                  `json:"credential_template_id,omitempty"`
	GrantType                 string                  `json:"grant_type,omitempty"`
	OpState                   string                  `json:"op_state,omitempty"`
	ResponseType              string                  `json:"response_type,omitempty"`
	Scope                     []string                `json:"scope,omitempty"`
	UserPinRequired           *bool                   `json:"user_pin_required,omitempty"`
}

type initiateOIDC4VCResponse struct {
	InitiateIssuanceUrl string `json:"initiate_issuance_url"`
	TxId                string `json:"tx_id"`
}

type accessTokenResponse struct {
	// The access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// String containing a nonce to be used to create a proof of possession of key material when requesting a credential.
	CNonce *string `json:"c_nonce,omitempty"`

	// Integer denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn *int `json:"c_nonce_expires_in,omitempty"`

	// The lifetime in seconds of the access token.
	ExpiresIn *int `json:"expires_in,omitempty"`

	// The refresh token, which can be used to obtain new access tokens.
	RefreshToken *string `json:"refresh_token,omitempty"`

	// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.
	Scope *string `json:"scope,omitempty"`

	// The type of the token issued.
	TokenType string `json:"token_type"`
}