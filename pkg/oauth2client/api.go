/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import (
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
)

var _ fosite.Client = (*Client)(nil)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypePreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	ResponseTypeCode = "code"

	TokenEndpointAuthMethodNone              = "none"
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"
)

// Client represents an OAuth2 client.
type Client struct {
	ID                      string              `json:"client_id"`
	Name                    string              `json:"client_name"`
	URI                     string              `json:"client_uri"`
	Secret                  []byte              `json:"client_secret,omitempty"`
	SecretExpiresAt         int64               `json:"client_secret_expires_at,omitempty"`
	RotatedSecrets          [][]byte            `json:"rotated_secrets,omitempty"`
	RedirectURIs            []string            `json:"redirect_uris"`
	GrantTypes              []string            `json:"grant_types"`
	ResponseTypes           []string            `json:"response_types"`
	Scopes                  []string            `json:"scopes"`
	Audience                []string            `json:"audience"`
	LogoURI                 string              `json:"logo_uri,omitempty"`
	Contacts                []string            `json:"contacts,omitempty"`
	TermsOfServiceURI       string              `json:"tos_uri,omitempty"`
	PolicyURI               string              `json:"policy_uri,omitempty"`
	JSONWebKeysURI          string              `json:"jwks_uri,omitempty"`
	JSONWebKeys             *jose.JSONWebKeySet `json:"jwks,omitempty"`
	SoftwareID              string              `json:"software_id,omitempty"`
	SoftwareVersion         string              `json:"software_version,omitempty"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method,omitempty"`
	CreatedAt               time.Time           `json:"created_at,omitempty" db:"created_at"`
}

// GetID returns the client id.
func (c *Client) GetID() string {
	return c.ID
}

// GetHashedSecret returns the hashed client secret.
func (c *Client) GetHashedSecret() []byte {
	return c.Secret
}

// GetRedirectURIs returns the client redirect URIs.
func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetGrantTypes returns the client grant types.
func (c *Client) GetGrantTypes() fosite.Arguments {
	if len(c.GrantTypes) == 0 {
		return fosite.Arguments{GrantTypeAuthorizationCode}
	}

	return c.GrantTypes
}

// GetResponseTypes returns the client response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		return fosite.Arguments{ResponseTypeCode}
	}

	return c.ResponseTypes
}

// GetScopes returns the client scopes.
func (c *Client) GetScopes() fosite.Arguments {
	return c.Scopes
}

// IsPublic returns true if the client is public.
func (c *Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == "none"
}

// GetAudience returns the client audience.
func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}

// GrantTypesSupported returns grant types supported by the VCS OIDC provider.
func GrantTypesSupported() []string {
	return []string{
		GrantTypeAuthorizationCode,
		GrantTypePreAuthorizedCode,
	}
}

// ResponseTypesSupported returns response types supported by the VCS OIDC provider.
func ResponseTypesSupported() []string {
	return []string{
		ResponseTypeCode,
	}
}

// TokenEndpointAuthMethodsSupported returns client authentication methods supported by the VCS token endpoint.
func TokenEndpointAuthMethodsSupported() []string {
	return []string{
		TokenEndpointAuthMethodNone,
		TokenEndpointAuthMethodClientSecretBasic,
		TokenEndpointAuthMethodClientSecretPost,
	}
}
