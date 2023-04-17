/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
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

type TransactionState int16

const (
	TransactionStateUnknown                         = TransactionState(0)
	TransactionStateIssuanceInitiated               = TransactionState(1)
	TransactionStatePreAuthCodeValidated            = TransactionState(2) // pre-auth only
	TransactionStateAwaitingIssuerOIDCAuthorization = TransactionState(3) // auth only
	TransactionStateIssuerOIDCAuthorizationDone     = TransactionState(4)
	TransactionStateCredentialsIssued               = TransactionState(5)
)

// ClaimData represents user claims in pre-auth code flow.
type ClaimData struct {
	EncryptedData *dataprotect.EncryptedData `json:"encrypted_data"`
}

type ClaimDataStore claimDataStore

// TransactionData is the transaction data stored in the underlying storage.
type TransactionData struct {
	ProfileID                          profileapi.ID
	OrgID                              string
	CredentialTemplate                 *profileapi.CredentialTemplate
	CredentialFormat                   vcsverifiable.Format
	OIDCCredentialFormat               vcsverifiable.OIDCFormat
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	ClaimEndpoint                      string
	ClientScope                        []string
	RedirectURI                        string
	GrantType                          string
	ResponseType                       string
	Scope                              []string
	AuthorizationDetails               *AuthorizationDetails
	IssuerAuthCode                     string
	IssuerToken                        string
	OpState                            string
	IsPreAuthFlow                      bool
	PreAuthCode                        string
	PreAuthCodeExpiresAt               *time.Time
	ClaimDataID                        string
	State                              TransactionState
	WebHookURL                         string
	UserPin                            string
	DID                                string
	CredentialExpiresAt                *time.Time
	CredentialName                     string
	CredentialDescription              string
}

// AuthorizationDetails are the VC-related details for VC issuance.
type AuthorizationDetails struct {
	Type      string
	Types     []string
	Format    vcsverifiable.Format
	Locations []string
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
	CredentialExpiresAt       *time.Time
	CredentialName            string
	CredentialDescription     string
}

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                TxID
	UserPin             string
}

// PrepareClaimDataAuthorizationRequest is the request to prepare the claim data authorization request.
type PrepareClaimDataAuthorizationRequest struct {
	ResponseType         string
	Scope                []string
	OpState              string
	AuthorizationDetails *AuthorizationDetails
}

type PrepareClaimDataAuthorizationResponse struct {
	ProfileID                          profileapi.ID
	TxID                               TxID
	ResponseType                       string
	Scope                              []string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
}

type PrepareCredential struct {
	TxID             TxID
	CredentialTypes  []string
	CredentialFormat vcsverifiable.Format
	DID              string
}

type PrepareCredentialResult struct {
	ProfileID               profileapi.ID
	Credential              *verifiable.Credential
	Format                  vcsverifiable.Format
	Retry                   bool
	EnforceStrictValidation bool
	OidcFormat              vcsverifiable.OIDCFormat
}

type InsertOptions struct {
	TTL time.Duration
}

type eventPayload struct {
	WebHook   string `json:"webHook,omitempty"`
	ProfileID string `json:"profileID,omitempty"`
	OrgID     string `json:"orgID,omitempty"`
	Error     string `json:"error,omitempty"`
}

type AuthorizationCodeGrant struct {
	IssuerState string `json:"issuer_state"`
}

type PreAuthorizationGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
	UserPinRequired   bool   `json:"user_pin_required"`
}

type CredentialOfferGrant struct {
	AuthorizationCode     *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizationGrant *PreAuthorizationGrant  `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"` // nolint:lll
}

type CredentialOffer struct {
	Format vcsverifiable.OIDCFormat `json:"format"`
	Types  []string                 `json:"types"`
}

type CredentialOfferResponse struct {
	CredentialIssuer string               `json:"credential_issuer"`
	Credentials      []CredentialOffer    `json:"credentials"`
	Grants           CredentialOfferGrant `json:"grants"`
}

type ServiceInterface interface {
	InitiateIssuance(ctx context.Context, req *InitiateIssuanceRequest, profile *profileapi.Issuer) (*InitiateIssuanceResponse, error) //nolint:lll
	PushAuthorizationDetails(ctx context.Context, opState string, ad *AuthorizationDetails) error
	PrepareClaimDataAuthorizationRequest(ctx context.Context, req *PrepareClaimDataAuthorizationRequest) (*PrepareClaimDataAuthorizationResponse, error) //nolint:lll
	StoreAuthorizationCode(ctx context.Context, opState string, code string) (TxID, error)
	ExchangeAuthorizationCode(ctx context.Context, opState string) (TxID, error)
	ValidatePreAuthorizedCodeRequest(ctx context.Context, preAuthorizedCode string, pin string) (*Transaction, error)
	PrepareCredential(ctx context.Context, req *PrepareCredential) (*PrepareCredentialResult, error)
}
