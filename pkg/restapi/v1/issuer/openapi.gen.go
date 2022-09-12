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

// Defines values for KMSConfigType.
const (
	KMSConfigTypeAws   KMSConfigType = "aws"
	KMSConfigTypeLocal KMSConfigType = "local"
	KMSConfigTypeWeb   KMSConfigType = "web"
)

// Defines values for VCConfigDidMethod.
const (
	VCConfigDidMethodKey VCConfigDidMethod = "key"
	VCConfigDidMethodOrb VCConfigDidMethod = "orb"
	VCConfigDidMethodWeb VCConfigDidMethod = "web"
)

// Defines values for VCConfigFormat.
const (
	JwtVc VCConfigFormat = "jwt_vc"
	LdpVc VCConfigFormat = "ldp_vc"
)

// Model for creating issuer profile.
type CreateIssuerProfileData struct {
	CredentialManifests *[]map[string]interface{} `json:"credentialManifests,omitempty"`

	// Model for KMS configuration.
	KmsConfig *KMSConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig *map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig VCConfig `json:"vcConfig"`
}

// Options for issuing credential.
type CredentialStatusOpt struct {
	Type string `json:"type"`
}

// Model for issuer credential.
type IssueCredentialData struct {
	// URI of the verifier.
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

// Model for issuer profile.
type IssuerProfile struct {
	// Is profile active? Can be modified using disable/enable profile endpoints.
	Active              bool                      `json:"active"`
	CredentialManifests *[]map[string]interface{} `json:"credentialManifests,omitempty"`

	// Short unique string across the VCS platform, to be used as a reference to this profile.
	Id string `json:"id"`

	// Model for KMS configuration.
	KmsConfig *KMSConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig *map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig VCConfig `json:"vcConfig"`
}

// Model for KMS configuration.
type KMSConfig struct {
	// Prefix of database used by local kms.
	DbPrefix *string `json:"dbPrefix,omitempty"`

	// Type of database used by local kms.
	DbType *string `json:"dbType,omitempty"`

	// URL to database used by local kms.
	DbURL *string `json:"dbURL,omitempty"`

	// KMS endpoint.
	Endpoint *string `json:"endpoint,omitempty"`

	// Path to secret lock used by local kms.
	SecretLockKeyPath *string `json:"secretLockKeyPath,omitempty"`

	// Type of kms used to create and store DID keys.
	Type KMSConfigType `json:"type"`
}

// Type of kms used to create and store DID keys.
type KMSConfigType string

// Model for updating issuer profile data.
type UpdateIssuerProfileData struct {
	// Issuer’s display name.
	Name *string `json:"name,omitempty"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig *map[string]interface{} `json:"oidcConfig,omitempty"`

	// URI of the issuer, Refer issuer from VC data model.
	Url *string `json:"url,omitempty"`
}

// Model for VC configuration.
type VCConfig struct {
	// Additional JSON-LD contexts the profile is going to use on top of standard W3C verifiable credential contexts and VCS contexts (status, signature suite, etc).
	Contexts *[]string `json:"contexts,omitempty"`

	// DID method of the DID to be used for signing.
	DidMethod VCConfigDidMethod `json:"didMethod"`

	// Supported VC formats.
	Format VCConfigFormat `json:"format"`

	// Type of key used for signing algorithms. Required only for signing algorithms that do not implicitly specify key type.
	KeyType *string `json:"keyType,omitempty"`

	// List of supported cryptographic signing algorithms.
	SigningAlgorithm string `json:"signingAlgorithm"`

	// DID to be used for signing.
	SigningDID string `json:"signingDID"`

	// Credential status type allowed for the profile.
	Status *map[string]interface{} `json:"status,omitempty"`
}

// DID method of the DID to be used for signing.
type VCConfigDidMethod string

// Supported VC formats.
type VCConfigFormat string

// PostIssuerProfilesJSONBody defines parameters for PostIssuerProfiles.
type PostIssuerProfilesJSONBody = CreateIssuerProfileData

// PutIssuerProfilesProfileIDJSONBody defines parameters for PutIssuerProfilesProfileID.
type PutIssuerProfilesProfileIDJSONBody = UpdateIssuerProfileData

// PostIssueCredentialsJSONBody defines parameters for PostIssueCredentials.
type PostIssueCredentialsJSONBody = map[string]interface{}

// PostIssuerProfilesJSONRequestBody defines body for PostIssuerProfiles for application/json ContentType.
type PostIssuerProfilesJSONRequestBody = PostIssuerProfilesJSONBody

// PutIssuerProfilesProfileIDJSONRequestBody defines body for PutIssuerProfilesProfileID for application/json ContentType.
type PutIssuerProfilesProfileIDJSONRequestBody = PutIssuerProfilesProfileIDJSONBody

// PostIssueCredentialsJSONRequestBody defines body for PostIssueCredentials for application/json ContentType.
type PostIssueCredentialsJSONRequestBody = PostIssueCredentialsJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create Profile
	// (POST /issuer/profiles)
	PostIssuerProfiles(ctx echo.Context) error
	// Delete Profile
	// (DELETE /issuer/profiles/{profileID})
	DeleteIssuerProfilesProfileID(ctx echo.Context, profileID string) error
	// Get Profile
	// (GET /issuer/profiles/{profileID})
	GetIssuerProfilesProfileID(ctx echo.Context, profileID string) error
	// Update Profile
	// (PUT /issuer/profiles/{profileID})
	PutIssuerProfilesProfileID(ctx echo.Context, profileID string) error
	// Activate Profile
	// (POST /issuer/profiles/{profileID}/activate)
	PostIssuerProfilesProfileIDActivate(ctx echo.Context, profileID string) error
	// Issue credential
	// (POST /issuer/profiles/{profileID}/credentials/issue)
	PostIssueCredentials(ctx echo.Context, profileID string) error
	// Deactivate Profile
	// (POST /issuer/profiles/{profileID}/deactivate)
	PostIssuerProfilesProfileIDDeactivate(ctx echo.Context, profileID string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// PostIssuerProfiles converts echo context to params.
func (w *ServerInterfaceWrapper) PostIssuerProfiles(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostIssuerProfiles(ctx)
	return err
}

// DeleteIssuerProfilesProfileID converts echo context to params.
func (w *ServerInterfaceWrapper) DeleteIssuerProfilesProfileID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DeleteIssuerProfilesProfileID(ctx, profileID)
	return err
}

// GetIssuerProfilesProfileID converts echo context to params.
func (w *ServerInterfaceWrapper) GetIssuerProfilesProfileID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetIssuerProfilesProfileID(ctx, profileID)
	return err
}

// PutIssuerProfilesProfileID converts echo context to params.
func (w *ServerInterfaceWrapper) PutIssuerProfilesProfileID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PutIssuerProfilesProfileID(ctx, profileID)
	return err
}

// PostIssuerProfilesProfileIDActivate converts echo context to params.
func (w *ServerInterfaceWrapper) PostIssuerProfilesProfileIDActivate(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostIssuerProfilesProfileIDActivate(ctx, profileID)
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

// PostIssuerProfilesProfileIDDeactivate converts echo context to params.
func (w *ServerInterfaceWrapper) PostIssuerProfilesProfileIDDeactivate(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "profileID" -------------
	var profileID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "profileID", runtime.ParamLocationPath, ctx.Param("profileID"), &profileID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter profileID: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.PostIssuerProfilesProfileIDDeactivate(ctx, profileID)
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

	router.POST(baseURL+"/issuer/profiles", wrapper.PostIssuerProfiles)
	router.DELETE(baseURL+"/issuer/profiles/:profileID", wrapper.DeleteIssuerProfilesProfileID)
	router.GET(baseURL+"/issuer/profiles/:profileID", wrapper.GetIssuerProfilesProfileID)
	router.PUT(baseURL+"/issuer/profiles/:profileID", wrapper.PutIssuerProfilesProfileID)
	router.POST(baseURL+"/issuer/profiles/:profileID/activate", wrapper.PostIssuerProfilesProfileIDActivate)
	router.POST(baseURL+"/issuer/profiles/:profileID/credentials/issue", wrapper.PostIssueCredentials)
	router.POST(baseURL+"/issuer/profiles/:profileID/deactivate", wrapper.PostIssuerProfilesProfileIDDeactivate)

}
