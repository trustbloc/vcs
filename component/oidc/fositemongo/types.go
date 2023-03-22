/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"errors"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/text/language"
)

var ErrDataNotFound = errors.New("data not found")

type genericDocument[T any] struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Record   T                  `bson:"record"`
	LookupID string             `bson:"_lookupId"`
	ExpireAt *time.Time         `bson:"expireAt,omitempty"`
}

type authorizeRequest struct {
	ResponseTypes        fosite.Arguments
	RedirectURI          *url.URL
	State                string
	HandledResponseTypes fosite.Arguments
	ResponseMode         fosite.ResponseModeType
	DefaultResponseMode  fosite.ResponseModeType
	ClientID             string
}

type request struct {
	ID                string
	RequestedAt       time.Time
	RequestedScope    fosite.Arguments
	GrantedScope      fosite.Arguments
	Form              url.Values
	RequestedAudience fosite.Arguments
	GrantedAudience   fosite.Arguments
	Lang              language.Tag
	ClientID          string
	SessionExtra      map[string]interface{}
}

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

func (c *Client) GetID() string {
	return c.ID
}

func (c *Client) GetHashedSecret() []byte {
	return c.Secret
}

func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *Client) GetGrantTypes() fosite.Arguments {
	if len(c.GrantTypes) == 0 {
		return fosite.Arguments{"authorization_code"}
	}

	return c.GrantTypes
}

func (c *Client) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		return fosite.Arguments{"code"}
	}

	return c.ResponseTypes
}

func (c *Client) GetScopes() fosite.Arguments {
	return c.Scopes
}

func (c *Client) IsPublic() bool {
	return c.Public
}

func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}
