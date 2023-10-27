/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dto

import (
	"errors"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/text/language"
)

const (
	ParSegment          = "fosite_par"
	AuthCodeSegment     = "fosite_auth_code"
	PkceSessionSegment  = "fosite_pkce_sessions"
	RefreshTokenSegment = "fosite_refresh_token_sessions" //nolint: gosec
	AccessTokenSegment  = "fosite_access_token_sessions"
)

var ErrDataNotFound = errors.New("data not found")

type AuthorizeRequest struct {
	ResponseTypes        fosite.Arguments
	RedirectURI          *url.URL
	State                string
	HandledResponseTypes fosite.Arguments
	ResponseMode         fosite.ResponseModeType
	DefaultResponseMode  fosite.ResponseModeType
	ClientID             string
}

type Request struct {
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
