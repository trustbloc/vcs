/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"github.com/ory/fosite"
)

var _ fosite.Session = (*Session)(nil) // make sure Session implements fosite.Session

// Session is the session for the OIDC4VC flow.
type Session struct {
	*fosite.DefaultSession `json:"token"`

	TxID TxID `json:"tx"`
}
