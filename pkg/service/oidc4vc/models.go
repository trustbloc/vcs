/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

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

// AuthorizationDetails parameter is used to convey the details about VC the wallet wants to obtain.
type AuthorizationDetails struct {
	Type           string
	CredentialType string
	Format         vcsverifiable.Format
	Locations      []string
}

// InitiateIssuanceInfo is the response from the issuer to the wallet with initiate issuance URL.
type InitiateIssuanceInfo struct {
	InitiateIssuanceURL string
	TxID                string
}

// TransactionData is the transaction data stored in the underlying storage.
type TransactionData struct {
	CredentialTemplate   *verifiable.Credential
	ClaimEndpoint        string
	GrantType            string
	ResponseType         string
	Scope                []string
	AuthorizationDetails *AuthorizationDetails
}

// TxID is the transaction ID.
type TxID string

// Transaction is the transaction for the initiate issuance interaction.
type Transaction struct {
	ID     TxID
	TxData TransactionData
}
