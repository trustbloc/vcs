/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"net/url"
	"time"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// TxID defines type for transaction ID.
type TxID string

// Transaction is the credential issuance transaction. Issuer creates a transaction to convey the intention of issuing a
// credential with the given parameters. The transaction is stored in the transaction store and its status is updated as
// the credential issuance progresses.
type Transaction struct {
	ID TxID
	TransactionData
}

// TransactionData is the transaction data stored in the underlying storage.
type TransactionData struct {
	CredentialTemplate                 *profileapi.CredentialTemplate
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	ClaimEndpoint                      string
	ClientID                           string
	GrantType                          string
	ResponseType                       string
	Scope                              []string
	AuthorizationDetails               *AuthorizationDetails
	OpState                            string
}

// AuthorizationDetails are the VC-related details for VC issuance.
type AuthorizationDetails struct {
	Type           string
	CredentialType string
	Format         vcsverifiable.Format
	Locations      []string
}

// OIDCConfiguration represents an OIDC configuration from well-know endpoint (/.well-known/openid-configuration).
type OIDCConfiguration struct {
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	ResponseTypesSupported             []string `json:"response_types_supported"`
	ScopesSupported                    []string `json:"scopes_supported"`
	GrantTypesSupported                []string `json:"grant_types_supported"`
	InitiateIssuanceEndpoint           string   `json:"initiate_issuance_endpoint"`
}

// InitiateIssuanceRequest is the request used by the Issuer to initiate the OIDC VC issuance interaction.
type InitiateIssuanceRequest struct {
	CredentialTemplateID      string
	ClientInitiateIssuanceURL string
	ClientWellKnownURL        string
	ClaimEndpoint             string
	GrantType                 string
	ResponseType              string
	Scope                     []string
	OpState                   string
}

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                TxID
}

type ClientWellKnownConfig struct {
	InitiateIssuanceEndpoint string `json:"initiate_issuance_endpoint"`
}

type PrepareClaimDataAuthorizationRequest struct {
	ResponseType         string
	RedirectURI          string
	Scope                string
	OpState              string
	AuthorizationDetails *AuthorizationDetails
}

type PrepareClaimDataAuthorizationResponse struct {
	AuthorizationParameters            *IssuerAuthorizationRequestParameters
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TxID                               TxID
}

type IssuerAuthorizationRequestParameters struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
}

type OIDC4AuthorizationState struct {
	RedirectURI       *url.URL          `json:"redirect_uri"`
	RespondMode       string            `json:"respond_mode"`
	AuthorizeResponse OIDC4AuthResponse `json:"authorize_response"`
}

type OIDC4AuthResponse struct {
	Header     map[string][]string
	Parameters map[string][]string
}

type InsertOptions struct {
	TTL time.Duration
}
