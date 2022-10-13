/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

// TxID is the transaction ID.
type TxID string

// Transaction is the transaction for the initiate issuance interaction.
type Transaction struct {
	ID     TxID
	TxData TransactionData
}

// TransactionData is the transaction data stored in the underlying storage.
type TransactionData struct {
	CredentialTemplate   *verifiable.Credential
	ClaimEndpoint        string
	GrantType            string
	ResponseType         string
	Scope                []string
	AuthorizationDetails *AuthorizationDetails
	OpState              string
}

// AuthorizationDetails parameter is used to convey the details about VC the wallet wants to obtain.
type AuthorizationDetails struct {
	Type           string
	CredentialType string
	Format         vcsverifiable.Format
	Locations      []string
}

// InitiateIssuanceRequest is the request used by the issuer to initiate OIDC VC issuance interaction.
type InitiateIssuanceRequest struct {
	CredentialTemplate        *verifiable.Credential
	ClientInitiateIssuanceURL string
	ClientWellKnownURL        string
	ClaimEndpoint             string
	GrantType                 string
	ResponseType              string
	Scope                     []string
	OpState                   string
	AuthorizationDetails      *AuthorizationDetails
}

// InitiateIssuanceInfo is the response from the issuer to the wallet with initiate issuance URL.
type InitiateIssuanceInfo struct {
	InitiateIssuanceURL string
	TxID                string
}

// PushedAuthorizationRequest is the request used by VCS OIDC public endpoints to push authorization requests (PAR).
type PushedAuthorizationRequest struct {
	AuthorizationDetails *AuthorizationDetails
	OpState              string
}

// PushedAuthorizationResponse is the response for PAR with request URL for OIDC authorization request redirects.
type PushedAuthorizationResponse struct {
	RequestURI string
	ExpiresIn  time.Duration
}
