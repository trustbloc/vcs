/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
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

type InitiateIssuanceResponseContentType = string

const (
	TransactionStateUnknown                         = TransactionState(0)
	TransactionStateIssuanceInitiated               = TransactionState(1)
	TransactionStatePreAuthCodeValidated            = TransactionState(2) // pre-auth only
	TransactionStateAwaitingIssuerOIDCAuthorization = TransactionState(3) // auth only
	TransactionStateIssuerOIDCAuthorizationDone     = TransactionState(4)
	TransactionStateCredentialsIssued               = TransactionState(5)
)

const (
	ContentTypeApplicationJSON InitiateIssuanceResponseContentType = echo.MIMEApplicationJSONCharsetUTF8
	ContentTypeApplicationJWT  InitiateIssuanceResponseContentType = "application/jwt"
	issuerIdentifierParts                                          = 2
)

// ClaimData represents user claims in pre-auth code flow.
type ClaimData struct {
	EncryptedData *dataprotect.EncryptedData `json:"encrypted_data"`
}

type ClaimDataStore claimDataStore

type TransactionStore transactionStore

// TransactionData is the transaction data stored in the underlying storage.
type TransactionData struct {
	ProfileID                          profileapi.ID
	ProfileVersion                     profileapi.Version
	OrgID                              string
	CredentialTemplate                 *profileapi.CredentialTemplate
	CredentialFormat                   vcsverifiable.Format // Format, that represents issued VC format (JWT, LDP).
	OIDCCredentialFormat               vcsverifiable.OIDCFormat
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	ClaimEndpoint                      string
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
	WalletInitiatedIssuance            bool
}

// AuthorizationDetails represents the domain model for Authorization Details request.
//
// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.1
type AuthorizationDetails struct {
	Type                      string
	Format                    vcsverifiable.Format
	Locations                 []string
	CredentialConfigurationID string
	CredentialDefinition      *CredentialDefinition
	CredentialIdentifiers     []string
}

func (ad *AuthorizationDetails) ToDTO() common.AuthorizationDetails {
	var credentialDefinition *common.CredentialDefinition
	if cd := ad.CredentialDefinition; cd != nil {
		credentialDefinition = &common.CredentialDefinition{
			Context:           &cd.Context,
			CredentialSubject: &cd.CredentialSubject,
			Type:              cd.Type,
		}
	}

	return common.AuthorizationDetails{
		CredentialConfigurationId: &ad.CredentialConfigurationID,
		CredentialDefinition:      credentialDefinition,
		CredentialIdentifiers:     lo.ToPtr(ad.CredentialIdentifiers),
		Format:                    lo.ToPtr(string(ad.Format)),
		Locations:                 &ad.Locations,
		Type:                      ad.Type,
	}
}

// CredentialDefinition contains the detailed description of the credential type.
type CredentialDefinition struct {
	// For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context           []string
	CredentialSubject map[string]interface{}
	Type              []string
}

// IssuerIDPOIDCConfiguration represents an Issuer's IDP OIDC configuration
// from well-know endpoint (usually: /.well-known/openid-configuration).
type IssuerIDPOIDCConfiguration struct {
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
	WalletInitiatedIssuance   bool
}

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                TxID
	UserPin             string
	Tx                  *Transaction                        `json:"-"`
	ContentType         InitiateIssuanceResponseContentType `json:"-"`
}

// PrepareClaimDataAuthorizationRequest is the request to prepare the claim data authorization request.
type PrepareClaimDataAuthorizationRequest struct {
	ResponseType         string
	Scope                []string
	OpState              string
	AuthorizationDetails *AuthorizationDetails
}

type PrepareClaimDataAuthorizationResponse struct {
	WalletInitiatedFlow                *common.WalletInitiatedFlowData
	ProfileID                          profileapi.ID
	ProfileVersion                     profileapi.Version
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
	AudienceClaim    string
	HashedToken      string
}

type PrepareCredentialResult struct {
	ProfileID               profileapi.ID
	ProfileVersion          profileapi.Version
	Credential              *verifiable.Credential
	Format                  vcsverifiable.Format
	Retry                   bool
	EnforceStrictValidation bool
	OidcFormat              vcsverifiable.OIDCFormat
	CredentialTemplate      *profileapi.CredentialTemplate
	NotificationID          *string
}

type InsertOptions struct {
	TTL time.Duration
}

type AuthorizeState struct {
	RedirectURI         *url.URL                        `json:"redirect_uri"`
	RespondMode         string                          `json:"respond_mode"`
	Header              map[string][]string             `json:"header"`
	Parameters          map[string][]string             `json:"parameters"`
	WalletInitiatedFlow *common.WalletInitiatedFlowData `json:"wallet_initiated_flow"`
}

type EventPayload struct {
	WebHook               string `json:"webHook,omitempty"`
	ProfileID             string `json:"profileID,omitempty"`
	ProfileVersion        string `json:"profileVersion,omitempty"`
	CredentialTemplateID  string `json:"credentialTemplateID,omitempty"`
	OrgID                 string `json:"orgID,omitempty"`
	WalletInitiatedFlow   bool   `json:"walletInitiatedFlow"`
	PinRequired           bool   `json:"pinRequired"`
	PreAuthFlow           bool   `json:"preAuthFlow"`
	Format                string `json:"format,omitempty"`
	InitiateIssuanceURL   string `json:"initiateIssuanceURL,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	Error                 string `json:"error,omitempty"`
	ErrorCode             string `json:"errorCode,omitempty"`
	ErrorComponent        string `json:"errorComponent,omitempty"`
}

type AuthorizationCodeGrant struct {
	IssuerState string `json:"issuer_state"`
}

type PreAuthorizationGrant struct {
	PreAuthorizedCode string  `json:"pre-authorized_code"`
	TxCode            *TxCode `json:"tx_code,omitempty"`
}

type TxCode struct {
	InputMode   string `json:"input_mode"`
	Length      int    `json:"length"`
	Description string `json:"description"`
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
	CredentialIssuer           string               `json:"credential_issuer"`
	CredentialConfigurationIDs []string             `json:"credential_configuration_ids"`
	Grants                     CredentialOfferGrant `json:"grants"`
}

type ServiceInterface interface {
	InitiateIssuance(
		ctx context.Context,
		req *InitiateIssuanceRequest,
		profile *profileapi.Issuer,
	) (*InitiateIssuanceResponse, error)
	PushAuthorizationDetails(ctx context.Context, opState string, ad *AuthorizationDetails) error
	PrepareClaimDataAuthorizationRequest(
		ctx context.Context,
		req *PrepareClaimDataAuthorizationRequest,
	) (*PrepareClaimDataAuthorizationResponse, error)
	StoreAuthorizationCode(
		ctx context.Context,
		opState string,
		code string,
		flowData *common.WalletInitiatedFlowData,
	) (TxID, error)
	ExchangeAuthorizationCode(
		ctx context.Context,
		opState,
		clientID,
		clientAssertionType,
		clientAssertion string,
	) (*ExchangeAuthorizationCodeResult, error)
	ValidatePreAuthorizedCodeRequest(
		ctx context.Context,
		preAuthorizedCode,
		pin,
		clientID,
		clientAssertionType,
		clientAssertion string,
	) (*Transaction, error)
	PrepareCredential(ctx context.Context, req *PrepareCredential) (*PrepareCredentialResult, error)
}

type Ack struct {
	HashedToken    string `json:"hashed_token"`
	ProfileID      string `json:"profile_id"`
	ProfileVersion string `json:"profile_version"`
	TxID           TxID   `json:"tx_id"`
	WebHookURL     string `json:"webhook_url"`
	OrgID          string `json:"org_id"`
}

type AckRemote struct {
	HashedToken      string `json:"hashed_token"`
	ID               string `json:"id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description"`
	IssuerIdentifier string `json:"issuer_identifier"`
}

type ExchangeAuthorizationCodeResult struct {
	TxID                 TxID
	AuthorizationDetails *AuthorizationDetails
}

var ErrDataNotFound = errors.New("data not found")
