/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vcstatestore

import "net/url"

type AuthorizeState struct {
	RedirectURI *url.URL            `json:"redirect_uri"`
	RespondMode string              `json:"respond_mode"`
	Header      map[string][]string `json:"header"`
	Parameters  map[string][]string `json:"parameters"`
}
