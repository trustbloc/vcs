/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	util "github.com/trustbloc/did-go/doc/util/time"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

type initiateOIDC4VCIResponse struct {
	OfferCredentialURL string  `json:"offer_credential_url"`
	TxId               string  `json:"tx_id"`
	UserPin            *string `json:"user_pin"`
}

type initiateOIDC4VPRequest struct {
	PresentationDefinitionId      string                         `json:"presentationDefinitionId,omitempty"`
	PresentationDefinitionFilters *presentationDefinitionFilters `json:"presentationDefinitionFilters,omitempty"`
	Scopes                        []string                       `json:"scopes,omitempty"`
}

type presentationDefinitionFilters struct {
	Fields *[]string `json:"fields,omitempty"`
}

type initiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxId                 string `json:"txID"`
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

type credentialIssuanceHistoryData struct {
	CredentialId    string   `json:"credential_id"`
	CredentialTypes []string `json:"credential_types"`
	ExpirationDate  string   `json:"expiration_date,omitempty"`
	IssuanceDate    string   `json:"issuance_date,omitempty"`
	Issuer          string   `json:"issuer"`
	TransactionId   string   `json:"transaction_id,omitempty"`
}

type credentialMetadata struct {
	Format         vcsverifiable.Format              `json:"format,omitempty"`
	Type           []string                          `json:"type,omitempty"`
	SubjectData    interface{}                       `json:"subjectData,omitempty"`
	Issuer         interface{}                       `json:"issuer,omitempty"`
	IssuanceDate   *util.TimeWrapper                 `json:"issuanceDate,omitempty"`
	ExpirationDate *util.TimeWrapper                 `json:"expirationDate,omitempty"`
	CustomClaims   map[string]map[string]interface{} `json:"customClaims,omitempty"`
	Attachments    []*oidc4vp.Attachment             `json:"attachments,omitempty"`
	ValidFrom      *util.TimeWrapper                 `json:"validFrom,omitempty"`
	ValidUntil     *util.TimeWrapper                 `json:"validUntil,omitempty"`
}

type retrievedCredentialClaims map[string]credentialMetadata
