// Package verifier provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package verifier

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/oapi-codegen/runtime"
)

// InitiateOIDC4VPData defines model for InitiateOIDC4VPData.
type InitiateOIDC4VPData struct {
	CustomURLScheme               *string                        `json:"customURLScheme,omitempty"`
	DynamicPresentationFilters    *PresentationDynamicFilters    `json:"dynamicPresentationFilters,omitempty"`
	PresentationDefinitionFilters *PresentationDefinitionFilters `json:"presentationDefinitionFilters,omitempty"`
	PresentationDefinitionId      *string                        `json:"presentationDefinitionId,omitempty"`
	Purpose                       *string                        `json:"purpose,omitempty"`

	// Scopes List of custom scopes that defines additional claims requested from Holder to Verifier.
	Scopes *[]string `json:"scopes,omitempty"`
}

// InitiateOIDC4VPResponse defines model for InitiateOIDC4VPResponse.
type InitiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxID                 string `json:"txID"`
}

// PresentationDefinitionFilters defines model for PresentationDefinitionFilters.
type PresentationDefinitionFilters struct {
	Fields *[]string `json:"fields,omitempty"`
}

// PresentationDynamicFilters defines model for PresentationDynamicFilters.
type PresentationDynamicFilters struct {
	// Context List of @contexts of the VC.
	Context *[]string `json:"context,omitempty"`

	// Type VC type.
	Type *string `json:"type,omitempty"`
}

// PresentationResult Presentation result.
type PresentationResult struct {
	// Verified Presentation verification result.
	Verified bool `json:"verified"`
}

// VerifyCredentialCheckResult Verify credential response containing failure check details.
type VerifyCredentialCheckResult struct {
	// Check Check title.
	Check string `json:"check"`

	// Error Error message.
	Error string `json:"error"`

	// VerificationMethod Verification method.
	VerificationMethod string `json:"verificationMethod"`
}

// VerifyCredentialData Model for credential verification.
type VerifyCredentialData struct {
	// Credential Credential in jws(string) or jsonld(object) formats. Backward compatibility, use verifiableCredential.
	// Deprecated:
	Credential *any `json:"credential,omitempty"`

	// Options Options for verify credential.
	Options *VerifyCredentialOptions `json:"options,omitempty"`

	// VerifiableCredential Credential in jws(string) or jsonld(object) formats.
	VerifiableCredential *any `json:"verifiableCredential,omitempty"`
}

// VerifyCredentialOptions Options for verify credential.
type VerifyCredentialOptions struct {
	// Challenge Chalange is added to the proof.
	Challenge *string `json:"challenge,omitempty"`

	// Domain Domain is added to the proof.
	Domain *string `json:"domain,omitempty"`
}

// VerifyCredentialResponse Model for response of credentials verification.
type VerifyCredentialResponse struct {
	Checks *[]VerifyCredentialCheckResult `json:"checks,omitempty"`
}

// VerifyPresentationData Model for presentation verification.
type VerifyPresentationData struct {
	// Options Options for verify presentation.
	Options *VerifyPresentationOptions `json:"options,omitempty"`

	// VerifiablePresentation Presentation in jws(string) or jsonld(object) formats.
	VerifiablePresentation any `json:"verifiablePresentation"`
}

// VerifyPresentationOptions Options for verify presentation.
type VerifyPresentationOptions struct {
	// Challenge Challenge is added to the proof.
	Challenge *string `json:"challenge,omitempty"`

	// Domain Domain is added to the proof.
	Domain *string `json:"domain,omitempty"`
}

// VerifyPresentationResponse Model for response of presentation verification.
type VerifyPresentationResponse struct {
	Checks            []string             `json:"checks"`
	CredentialResults []PresentationResult `json:"credentialResults"`
	Errors            *[]string            `json:"errors,omitempty"`

	// Presentation Presentation object.
	Presentation *map[string]interface{} `json:"presentation,omitempty"`

	// PresentationResult Presentation result.
	PresentationResult PresentationResult `json:"presentationResult"`
	Verified           bool               `json:"verified"`
	Warnings           *[]string          `json:"warnings,omitempty"`
}

// CheckAuthorizationResponseFormdataBody defines parameters for CheckAuthorizationResponse.
type CheckAuthorizationResponseFormdataBody struct {
	// Error Authorization response error code
	Error *string `form:"error" json:"error"`

	// ErrorDescription Authorization response error description
	ErrorDescription *string `form:"error_description" json:"error_description"`

	// IdToken ID Token serves as an authentication receipt and includes metadata about the VP Token.
	IdToken *string `form:"id_token" json:"id_token"`

	// State State from authorization request for correlation
	State *string `form:"state,omitempty" json:"state,omitempty"`

	// VpToken VP Token includes one or more Verifiable Presentations.
	VpToken *string `form:"vp_token" json:"vp_token"`
}

// CheckAuthorizationResponseFormdataRequestBody defines body for CheckAuthorizationResponse for application/x-www-form-urlencoded ContentType.
type CheckAuthorizationResponseFormdataRequestBody CheckAuthorizationResponseFormdataBody

// PostVerifyCredentialsJSONRequestBody defines body for PostVerifyCredentials for application/json ContentType.
type PostVerifyCredentialsJSONRequestBody = VerifyCredentialData

// InitiateOidcInteractionJSONRequestBody defines body for InitiateOidcInteraction for application/json ContentType.
type InitiateOidcInteractionJSONRequestBody = InitiateOIDC4VPData

// PostVerifyPresentationJSONRequestBody defines body for PostVerifyPresentation for application/json ContentType.
type PostVerifyPresentationJSONRequestBody = VerifyPresentationData

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Used by verifier applications to initiate OpenID presentation flow through VCS
	// (POST /verifier/interactions/authorization-response)
	CheckAuthorizationResponse(ctx echo.Context) error
	// Used by verifier applications to get claims obtained during oidc4vp interaction.
	// (GET /verifier/interactions/{txID}/claim)
	RetrieveInteractionsClaim(ctx echo.Context, txid string) error
	// Verify credential
	// (POST /verifier/profiles/{profileID}/{profileVersion}/credentials/verify)
	PostVerifyCredentials(ctx echo.Context, profileID string, profileVersion string) error
	// Used by verifier applications to initiate OpenID presentation flow through VCS
	// (POST /verifier/profiles/{profileID}/{profileVersion}/interactions/initiate-oidc)
	InitiateOidcInteraction(ctx echo.Context, profileID string, profileVersion string) error
	// Verify presentation
	// (POST /verifier/profiles/{profileID}/{profileVersion}/presentations/verify)
	PostVerifyPresentation(ctx echo.Context, profileID string, profileVersion string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// CheckAuthorizationResponse converts echo context to params.
func (w *ServerInterfaceWrapper) CheckAuthorizationResponse(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.CheckAuthorizationResponse(ctx)
	return err
}

// RetrieveInteractionsClaim converts echo context to params.
func (w *ServerInterfaceWrapper) RetrieveInteractionsClaim(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "txID" -------------
	var txid string

	err = runtime.BindStyledParameterWithOptions("simple", "txID", ctx.Param("txID"), &txid, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter txID: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.RetrieveInteractionsClaim(ctx, txid)
	return err
}

// PostVerifyCredentials converts echo context to params.
func (w *ServerInterfaceWrapper) PostVerifyCredentials(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithOptions("simple", "profileID", ctx.Param("profileID"), &profileID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// ------------- Path parameter "profileVersion" -------------
	var profileVersion string

	err = runtime.BindStyledParameterWithOptions("simple", "profileVersion", ctx.Param("profileVersion"), &profileVersion, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileVersion: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.PostVerifyCredentials(ctx, profileID, profileVersion)
	return err
}

// InitiateOidcInteraction converts echo context to params.
func (w *ServerInterfaceWrapper) InitiateOidcInteraction(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithOptions("simple", "profileID", ctx.Param("profileID"), &profileID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// ------------- Path parameter "profileVersion" -------------
	var profileVersion string

	err = runtime.BindStyledParameterWithOptions("simple", "profileVersion", ctx.Param("profileVersion"), &profileVersion, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileVersion: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.InitiateOidcInteraction(ctx, profileID, profileVersion)
	return err
}

// PostVerifyPresentation converts echo context to params.
func (w *ServerInterfaceWrapper) PostVerifyPresentation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithOptions("simple", "profileID", ctx.Param("profileID"), &profileID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// ------------- Path parameter "profileVersion" -------------
	var profileVersion string

	err = runtime.BindStyledParameterWithOptions("simple", "profileVersion", ctx.Param("profileVersion"), &profileVersion, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileVersion: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.PostVerifyPresentation(ctx, profileID, profileVersion)
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

	router.POST(baseURL+"/verifier/interactions/authorization-response", wrapper.CheckAuthorizationResponse)
	router.GET(baseURL+"/verifier/interactions/:txID/claim", wrapper.RetrieveInteractionsClaim)
	router.POST(baseURL+"/verifier/profiles/:profileID/:profileVersion/credentials/verify", wrapper.PostVerifyCredentials)
	router.POST(baseURL+"/verifier/profiles/:profileID/:profileVersion/interactions/initiate-oidc", wrapper.InitiateOidcInteraction)
	router.POST(baseURL+"/verifier/profiles/:profileID/:profileVersion/presentations/verify", wrapper.PostVerifyPresentation)

}
