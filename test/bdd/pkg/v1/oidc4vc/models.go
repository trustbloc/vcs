/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"

type initiateOIDC4CIRequest struct {
	ClaimData                 *map[string]interface{} `json:"claim_data,omitempty"`
	ClaimEndpoint             string                  `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceUrl string                  `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string                  `json:"client_wellknown,omitempty"`
	CredentialTemplateId      string                  `json:"credential_template_id,omitempty"`
	GrantType                 string                  `json:"grant_type,omitempty"`
	OpState                   string                  `json:"op_state,omitempty"`
	ResponseType              string                  `json:"response_type,omitempty"`
	Scope                     []string                `json:"scope,omitempty"`
	UserPinRequired           bool                    `json:"user_pin_required,omitempty"`
}

type initiateOIDC4CIResponse struct {
	OfferCredentialURL string  `json:"offer_credential_url"`
	TxId               string  `json:"tx_id"`
	UserPin            *string `json:"user_pin"`
}

type clientRegistrationRequest struct {
	ClientName              *string                 `json:"client_name,omitempty"`
	ClientUri               *string                 `json:"client_uri,omitempty"`
	Contacts                *[]string               `json:"contacts,omitempty"`
	GrantTypes              *[]string               `json:"grant_types,omitempty"`
	Jwks                    *map[string]interface{} `json:"jwks,omitempty"`
	JwksUri                 *string                 `json:"jwks_uri,omitempty"`
	LogoUri                 *string                 `json:"logo_uri,omitempty"`
	PolicyUri               *string                 `json:"policy_uri,omitempty"`
	RedirectUris            *[]string               `json:"redirect_uris,omitempty"`
	ResponseTypes           *[]string               `json:"response_types,omitempty"`
	Scope                   *string                 `json:"scope,omitempty"`
	SoftwareId              *string                 `json:"software_id,omitempty"`
	SoftwareVersion         *string                 `json:"software_version,omitempty"`
	TokenEndpointAuthMethod *string                 `json:"token_endpoint_auth_method,omitempty"`
	TosUri                  *string                 `json:"tos_uri,omitempty"`
}

type clientRegistrationResponse struct {
	ClientId                string                  `json:"client_id"`
	ClientIdIssuedAt        *int                    `json:"client_id_issued_at,omitempty"`
	ClientName              *string                 `json:"client_name,omitempty"`
	ClientSecret            *string                 `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int                    `json:"client_secret_expires_at,omitempty"`
	ClientUri               *string                 `json:"client_uri,omitempty"`
	Contacts                *[]string               `json:"contacts,omitempty"`
	GrantTypes              []string                `json:"grant_types"`
	Jwks                    *map[string]interface{} `json:"jwks,omitempty"`
	JwksUri                 *string                 `json:"jwks_uri,omitempty"`
	LogoUri                 *string                 `json:"logo_uri,omitempty"`
	PolicyUri               *string                 `json:"policy_uri,omitempty"`
	RedirectUris            *[]string               `json:"redirect_uris,omitempty"`
	ResponseTypes           *[]string               `json:"response_types,omitempty"`
	Scope                   *string                 `json:"scope,omitempty"`
	SoftwareId              *string                 `json:"software_id,omitempty"`
	SoftwareVersion         *string                 `json:"software_version,omitempty"`
	TokenEndpointAuthMethod string                  `json:"token_endpoint_auth_method"`
	TosUri                  *string                 `json:"tos_uri,omitempty"`
}

type credentialOfferResponse struct {
	CredentialIssuer string               `json:"credential_issuer"`
	Credentials      []credentialOffer    `json:"credentials"`
	Grants           credentialOfferGrant `json:"grants"`
}

type credentialOffer struct {
	Format vcsverifiable.OIDCFormat `json:"format"`
	Types  []string                 `json:"types"`
}

type credentialOfferGrant struct {
	AuthorizationCode *authorizationCodeGrant `json:"authorization_code,omitempty"`
}

type authorizationCodeGrant struct {
	IssuerState string `json:"issuer_state"`
}

type wellKnownOpenIDConfiguration struct {
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	PreAuthorizedGrantAnonymousAccessSupported bool     `json:"pre-authorized_grant_anonymous_access_supported"`
	RegistrationEndpoint                       *string  `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpoint                              string   `json:"token_endpoint"`
}
