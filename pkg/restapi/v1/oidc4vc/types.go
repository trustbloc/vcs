/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"net/url"
)

type AuthResponder struct {
	RedirectURI       *url.URL     `json:"redirect_uri"`
	RespondMode       string       `json:"respond_mode"`
	AuthorizeResponse AuthResponse `json:"authorize_response"`
}

type AuthResponse struct {
	Header     map[string][]string
	Parameters map[string][]string
}
