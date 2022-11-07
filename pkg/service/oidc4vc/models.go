/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
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
	CredentialFormat                   vcsverifiable.Format
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	ClaimEndpoint                      string
	ClientID                           string
	ClientSecret                       string
	GrantType                          string
	ResponseType                       string
	Scope                              []string
	AuthorizationDetails               *AuthorizationDetails
	IssuerAuthCode                     string
	IssuerToken                        string
	OpState                            string
	UserPinRequired                    bool
	IsPreAuthFlow                      bool
	PreAuthCode                        string
	ClaimData                          map[string]interface{}
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
	ClaimData                 map[string]interface{}
	UserPinRequired           bool
}

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                TxID
}

// PrepareClaimDataAuthorizationRequest is the request to prepare the claim data authorization request.
type PrepareClaimDataAuthorizationRequest struct {
	ResponseType         string
	Scope                []string
	OpState              string
	AuthorizationDetails *AuthorizationDetails
}

type PrepareClaimDataAuthorizationResponse struct {
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	AuthorizationParameters            *OAuthParameters
	TxID                               TxID
}

type OAuthParameters struct {
	ClientID     string
	ClientSecret string
	ResponseType string
	Scope        []string
}

type InsertOptions struct {
	TTL time.Duration
}
