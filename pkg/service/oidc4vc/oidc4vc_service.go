/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import "github.com/hyperledger/aries-framework-go/pkg/doc/cm"

type IssuanceRequest struct {
	CredentialManifest        *cm.CredentialManifest
	ClientInitiateIssuanceURL string
	ClientWellKnownURL        string
	ClaimEndpoint             string
	GrantType                 string
	ResponseType              string
	Scope                     []string
	AuthorizationDetails      string // TODO: define type
}

type InteractionInfo struct {
	InitiateIssuanceURL string
	TxID                string
}
