/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"time"

	util "github.com/trustbloc/did-go/doc/util/time"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type initiateOIDC4VCIRequest struct {
	// Deprecated. Use CredentialConfiguration instead.
	ClaimData *map[string]interface{} `json:"claim_data,omitempty"`
	// Deprecated. Use CredentialConfiguration instead.
	ClaimEndpoint             string `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceUrl string `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string `json:"client_wellknown,omitempty"`
	// Deprecated. Use CredentialConfiguration instead.
	CredentialTemplateId string   `json:"credential_template_id,omitempty"`
	GrantType            string   `json:"grant_type,omitempty"`
	OpState              string   `json:"op_state,omitempty"`
	ResponseType         string   `json:"response_type,omitempty"`
	Scope                []string `json:"scope,omitempty"`
	UserPinRequired      bool     `json:"user_pin_required,omitempty"`
	// MultiCredentialIssuance aimed to initialise multi credential issuance.
	CredentialConfiguration []InitiateIssuanceCredentialConfiguration `json:"credential_configuration,omitempty"`
}

type InitiateIssuanceCredentialConfiguration struct {
	ClaimData             map[string]interface{} `json:"claim_data,omitempty"`
	ClaimEndpoint         string                 `json:"claim_endpoint,omitempty"`
	CredentialTemplateId  string                 `json:"credential_template_id,omitempty"`
	CredentialExpiresAt   *time.Time             `json:"credential_expires_at,omitempty"`
	CredentialName        string                 `json:"credential_name,omitempty"`
	CredentialDescription string                 `json:"credential_description,omitempty"`

	Compose *issuer.DeprecatedComposeOIDC4CICredential `json:"compose,omitempty"`
}

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
}

type retrievedCredentialClaims map[string]credentialMetadata
