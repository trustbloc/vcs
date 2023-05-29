/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import "github.com/ory/fosite"

var _ fosite.Client = (*Client)(nil)

// Client represents an OAuth2 client.
type Client struct {
	ID             string   `json:"id"`
	Secret         []byte   `json:"client_secret,omitempty"`
	RotatedSecrets [][]byte `json:"rotated_secrets,omitempty"`
	RedirectURIs   []string `json:"redirect_uris"`
	GrantTypes     []string `json:"grant_types"`
	ResponseTypes  []string `json:"response_types"`
	Scopes         []string `json:"scopes"`
	Audience       []string `json:"audience"`
	Public         bool     `json:"public"`
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
		return fosite.Arguments{"authorization_code"}
	}

	return c.GrantTypes
}

// GetResponseTypes returns the client response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		return fosite.Arguments{"code"}
	}

	return c.ResponseTypes
}

// GetScopes returns the client scopes.
func (c *Client) GetScopes() fosite.Arguments {
	return c.Scopes
}

// IsPublic returns true if the client is public.
func (c *Client) IsPublic() bool {
	return c.Public
}

// GetAudience returns the client audience.
func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}
