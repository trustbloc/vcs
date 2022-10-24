// Package issuer provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.11.0 DO NOT EDIT.
package issuer

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// Credential status.
type CredentialStatus struct {
	Status string `json:"status"`
	Type   string `json:"type"`
}

// Options for issuing credential.
type CredentialStatusOpt struct {
	Type string `json:"type"`
}

// Model for Initiate OIDC Credential Issuance Request.
type InitiateOIDC4VCRequest struct {
	// Customizes what kind of access Issuer wants to give to VCS.
	AuthorizationDetails *string `json:"authorization_details,omitempty"`

	// Claim endpoint of the Issuer from where credential claim data has to be requested after successfully acquiring access tokens.
	ClaimEndpoint *string `json:"claim_endpoint,omitempty"`

	// URL of the issuance initiation endpoint of a Wallet. Takes precedence over client_wellknown request parameter. If both client_initiate_issuance_url and client_wellknown are not provided then response initiate issuance URL will contain custom initiate issuance URL in format openid-initiate-issuance://.
	ClientInitiateIssuanceUrl *string `json:"client_initiate_issuance_url,omitempty"`

	// String containing wallet/holder application OIDC client wellknown configuration URL.
	ClientWellknown *string `json:"client_wellknown,omitempty"`

	// Template of the credential to be issued while successfully concluding this interaction. REQUIRED, if the profile is configured to use multiple credential templates.
	CredentialTemplateId *string `json:"credential_template_id,omitempty"`

	// Issuer can provide custom grant types through this parameter. This grant type has to be used while exchanging an access token for authorization code in later steps. If not provided then default to authorization_code.
	GrantType *string `json:"grant_type,omitempty"`

	// String value created by the Credential Issuer and opaque to the Wallet that is used to bind the sub-sequent authentication request with the Credential Issuer to a context set up during previous steps. If the client receives a value for this parameter, it MUST include it in the subsequent Authentication Request to the Credential Issuer as the op_state parameter value. MUST NOT be used in Authorization Code flow when pre-authorized_code is present.
	OpState *string `json:"op_state,omitempty"`

	// Contains response type that issuer expects VCS to use while performing OIDC authorization request. Defaults to token.
	ResponseType *string `json:"response_type,omitempty"`

	// Contains scopes that issuer expects VCS to use while requesting authorization code for claim data. Defaults to openid.
	Scope *[]string `json:"scope,omitempty"`
}

// Model for Initiate OIDC Credential Issuance Response.
type InitiateOIDC4VCResponse struct {
	// OIDC4CI initiate issuance URL to be used by the Issuer to pass relevant information to the Wallet to initiate issuance flow. Supports both HTTP GET and HTTP Redirect. Issuers may present QR code containing request data for users to scan from their mobile Wallet app.
	InitiateIssuanceUrl string `json:"initiate_issuance_url"`

	// To be used by Issuer applications for correlation if needed.
	TxId string `json:"tx_id"`
}

// Model for issuer credential.
type IssueCredentialData struct {
	// Credential in jws(string) or jsonld(object) formats.
	Credential interface{} `json:"credential"`

	// Options for issuing credential.
	Options *IssueCredentialOptions `json:"options,omitempty"`
}

// Options for issuing credential.
type IssueCredentialOptions struct {
	// Chalange is added to the proof.
	Challenge *string `json:"challenge,omitempty"`

	// The date of the proof. If omitted system time will be used.
	Created *string `json:"created,omitempty"`

	// Options for issuing credential.
	CredentialStatus *CredentialStatusOpt `json:"credentialStatus,omitempty"`

	// Domain is added to the proof.
	Domain *string `json:"domain,omitempty"`

	// The URI of the verificationMethod used for the proof. If omitted first ed25519 public key of DID (Issuer or Profile DID) will be used.
	VerificationMethod *string `json:"verificationMethod,omitempty"`
}

// Model for Prepare Claim Data AuthZ Request
type PrepareClaimDataAuthZRequest struct {
	OpState   *string                `json:"op_state,omitempty"`
	Responder *PrepareClaimResponder `json:"responder,omitempty"`
}

// PrepareClaimDataAuthZResponse defines model for PrepareClaimDataAuthZResponse.
type PrepareClaimDataAuthZResponse struct {
	RedirectUri *string `json:"redirect_uri,omitempty"`
}

// PrepareClaimResponder defines model for PrepareClaimResponder.
type PrepareClaimResponder struct {
	AuthorizeResponse *map[string]interface{} `json:"authorize_response,omitempty"`
	RedirectUri       *map[string]interface{} `json:"redirect_uri,omitempty"`
	RespondMode       *string                 `json:"respond_mode,omitempty"`
}

// UpdateCredentialStatusRequest request struct for updating VC status.
type UpdateCredentialStatusRequest struct {
	CredentialID string `json:"credentialID"`

	// Credential status.
	CredentialStatus CredentialStatus `json:"credentialStatus"`
}

// PrepareClaimDataAuthzRequestJSONBody defines parameters for PrepareClaimDataAuthzRequest.
type PrepareClaimDataAuthzRequestJSONBody = PrepareClaimDataAuthZRequest

// PostIssueCredentialsJSONBody defines parameters for PostIssueCredentials.
type PostIssueCredentialsJSONBody = IssueCredentialData

// PostCredentialsStatusJSONBody defines parameters for PostCredentialsStatus.
type PostCredentialsStatusJSONBody = UpdateCredentialStatusRequest

// PostIssuerProfilesProfileIDInteractionsInitiateOidcJSONBody defines parameters for PostIssuerProfilesProfileIDInteractionsInitiateOidc.
type PostIssuerProfilesProfileIDInteractionsInitiateOidcJSONBody = InitiateOIDC4VCRequest

// PrepareClaimDataAuthzRequestJSONRequestBody defines body for PrepareClaimDataAuthzRequest for application/json ContentType.
type PrepareClaimDataAuthzRequestJSONRequestBody = PrepareClaimDataAuthzRequestJSONBody

// PostIssueCredentialsJSONRequestBody defines body for PostIssueCredentials for application/json ContentType.
type PostIssueCredentialsJSONRequestBody = PostIssueCredentialsJSONBody

// PostCredentialsStatusJSONRequestBody defines body for PostCredentialsStatus for application/json ContentType.
type PostCredentialsStatusJSONRequestBody = PostCredentialsStatusJSONBody

// PostIssuerProfilesProfileIDInteractionsInitiateOidcJSONRequestBody defines body for PostIssuerProfilesProfileIDInteractionsInitiateOidc for application/json ContentType.
type PostIssuerProfilesProfileIDInteractionsInitiateOidcJSONRequestBody = PostIssuerProfilesProfileIDInteractionsInitiateOidcJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Prepare oauth uri for issuer provider
	// (POST /issuer/interactions/prepare-claim-data-authz-request)
	PrepareClaimDataAuthzRequest(ctx echo.Context) error
	// Issue credential
	// (POST /issuer/profiles/{profileID}/credentials/issue)
	PostIssueCredentials(ctx echo.Context, profileID string) error
	// Updates credential status.
	// (POST /issuer/profiles/{profileID}/credentials/status)
	PostCredentialsStatus(ctx echo.Context, profileID string) error
	// Retrieves the credential status.
	// (GET /issuer/profiles/{profileID}/credentials/status/{statusID})
	GetCredentialsStatus(ctx echo.Context, profileID string, statusID string) error
	// Initiate OIDC Credential Issuance
	// (POST /issuer/profiles/{profileID}/interactions/initiate-oidc)
	PostIssuerProfilesProfileIDInteractionsInitiateOidc(ctx echo.Context, profileID string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// PrepareClaimDataAuthzRequest converts echo context to params.
func (w *ServerInterfaceWrapper) PrepareClaimDataAuthzRequest(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PrepareClaimDataAuthzRequest(ctx)
	return err
}

// PostIssueCredentials converts echo context to params.
func (w *ServerInterfaceWrapper) PostIssueCredentials(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostIssueCredentials(ctx, profileID)
	return err
}

// PostCredentialsStatus converts echo context to params.
func (w *ServerInterfaceWrapper) PostCredentialsStatus(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostCredentialsStatus(ctx, profileID)
	return err
}

// GetCredentialsStatus converts echo context to params.
func (w *ServerInterfaceWrapper) GetCredentialsStatus(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// ------------- Path parameter "statusID" -------------
	var statusID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "statusID", runtime.ParamLocationPath, ctx.Param("statusID"), &statusID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter statusID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetCredentialsStatus(ctx, profileID, statusID)
	return err
}

// PostIssuerProfilesProfileIDInteractionsInitiateOidc converts echo context to params.
func (w *ServerInterfaceWrapper) PostIssuerProfilesProfileIDInteractionsInitiateOidc(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostIssuerProfilesProfileIDInteractionsInitiateOidc(ctx, profileID)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
	RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST(baseURL+"/issuer/interactions/prepare-claim-data-authz-request", wrapper.PrepareClaimDataAuthzRequest)
	router.POST(baseURL+"/issuer/profiles/:profileID/credentials/issue", wrapper.PostIssueCredentials)
	router.POST(baseURL+"/issuer/profiles/:profileID/credentials/status", wrapper.PostCredentialsStatus)
	router.GET(baseURL+"/issuer/profiles/:profileID/credentials/status/:statusID", wrapper.GetCredentialsStatus)
	router.POST(baseURL+"/issuer/profiles/:profileID/interactions/initiate-oidc", wrapper.PostIssuerProfilesProfileIDInteractionsInitiateOidc)

}
