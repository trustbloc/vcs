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
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

type InitiateIssuanceResponseContentType = string

const (
	ContentTypeApplicationJSON InitiateIssuanceResponseContentType = echo.MIMEApplicationJSONCharsetUTF8
	ContentTypeApplicationJWT  InitiateIssuanceResponseContentType = "application/jwt"
	issuerIdentifierParts                                          = 2
)

type ClaimDataStore claimDataStore

type TransactionStore transactionStore

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
	ClientInitiateIssuanceURL string
	ClientWellKnownURL        string
	GrantType                 string
	ResponseType              string
	Scope                     []string
	OpState                   string
	UserPinRequired           bool
	WalletInitiatedIssuance   bool
	// CredentialConfiguration aimed to initialise multi credential issuance.
	CredentialConfiguration []InitiateIssuanceCredentialConfiguration
}

type InitiateIssuanceCredentialConfiguration struct {
	ClaimData             map[string]interface{}             `json:"claim_data,omitempty"`
	ComposeCredential     *InitiateIssuanceComposeCredential `json:"compose_credential,omitempty"`
	ClaimEndpoint         string                             `json:"claim_endpoint,omitempty"`
	CredentialTemplateID  string                             `json:"credential_template_id,omitempty"`
	CredentialExpiresAt   *time.Time                         `json:"credential_expires_at,omitempty"`
	CredentialName        string                             `json:"credential_name,omitempty"`
	CredentialDescription string                             `json:"credential_description,omitempty"`
}

type InitiateIssuanceComposeCredential struct {
	Credential              *map[string]interface{} `json:"credential,omitempty"`
	IDTemplate              string                  `json:"id_template"`
	OverrideIssuer          bool                    `json:"override_issuer"`
	OverrideSubjectDID      bool                    `json:"override_subject_did"`
	PerformStrictValidation bool                    `json:"perform_strict_validation,omitempty"`
}

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                issuecredential.TxID
	UserPin             string
	Tx                  *issuecredential.Transaction        `json:"-"`
	ContentType         InitiateIssuanceResponseContentType `json:"-"`
}

// PrepareClaimDataAuthorizationRequest is the request to prepare the claim data authorization request.
type PrepareClaimDataAuthorizationRequest struct {
	ResponseType         string
	Scope                []string
	OpState              string
	AuthorizationDetails []*issuecredential.AuthorizationDetails
}

type PrepareClaimDataAuthorizationResponse struct {
	WalletInitiatedFlow                *common.WalletInitiatedFlowData
	ProfileID                          profileapi.ID
	ProfileVersion                     profileapi.Version
	TxID                               issuecredential.TxID
	ResponseType                       string
	Scope                              []string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
}

type PrepareCredential struct {
	TxID               issuecredential.TxID
	CredentialRequests []*PrepareCredentialRequest
}

type PrepareCredentialRequest struct {
	CredentialTypes  []string
	CredentialFormat vcsverifiable.OIDCFormat
	DID              string
	AudienceClaim    string
	HashedToken      string
}

type PrepareCredentialResult struct {
	ProfileID      profileapi.ID
	ProfileVersion profileapi.Version
	Credentials    []*PrepareCredentialResultData
}

type PrepareCredentialResultData struct {
	Credential              *verifiable.Credential
	Format                  vcsverifiable.Format
	OidcFormat              vcsverifiable.OIDCFormat
	CredentialTemplate      *profileapi.CredentialTemplate
	Retry                   bool
	EnforceStrictValidation bool
	NotificationID          *string
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
	OrgID                 string `json:"orgID,omitempty"`
	WalletInitiatedFlow   bool   `json:"walletInitiatedFlow"`
	PinRequired           bool   `json:"pinRequired"`
	PreAuthFlow           bool   `json:"preAuthFlow"`
	InitiateIssuanceURL   string `json:"initiateIssuanceURL,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	Error                 string `json:"error,omitempty"`
	ErrorCode             string `json:"errorCode,omitempty"`
	ErrorComponent        string `json:"errorComponent,omitempty"`
	// Deprecated: use Credentials instead.
	CredentialTemplateID string `json:"credentialTemplateID,omitempty"`
	// Deprecated: use Credentials instead.
	Format        vcsverifiable.OIDCFormat            `json:"format,omitempty"`
	Credentials   map[string]vcsverifiable.OIDCFormat `json:"credentials"`
	CredentialIDs []string                            `json:"credentialIDs"`
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
	PushAuthorizationDetails(ctx context.Context, opState string, ad []*issuecredential.AuthorizationDetails) error
	PrepareClaimDataAuthorizationRequest(
		ctx context.Context,
		req *PrepareClaimDataAuthorizationRequest,
	) (*PrepareClaimDataAuthorizationResponse, error)
	StoreAuthorizationCode(
		ctx context.Context,
		opState string,
		code string,
		flowData *common.WalletInitiatedFlowData,
	) (issuecredential.TxID, error)
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
	) (*issuecredential.Transaction, error)
	PrepareCredential(ctx context.Context, req *PrepareCredential) (*PrepareCredentialResult, error)
}

type Ack struct {
	HashedToken    string `json:"hashed_token"`
	ProfileID      string `json:"profile_id"`
	ProfileVersion string `json:"profile_version"`
	TxID           string `json:"tx_id"` // [tx ID]-[short uuid]
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
	TxID issuecredential.TxID
	// AuthorizationDetails REQUIRED when authorization_details parameter is used to request issuance
	// of a certain Credential type in Authorization Request. It MUST NOT be used otherwise.
	AuthorizationDetails []*issuecredential.AuthorizationDetails
}

var ErrDataNotFound = errors.New("data not found")
