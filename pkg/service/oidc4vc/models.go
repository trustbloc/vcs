/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

// TxID defines type for transaction ID.
type TxID string

// Transaction is the credential issuance transaction. Issuer creates a transaction to convey the intention of issuing a
// credential with the given parameters. The transaction is stored in the transaction store and its status is updated as
// the credential issuance progresses.
type Transaction struct {
	ID TxID
	TransactionData
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

// AuthorizationDetails are the details for VC issuance.
type AuthorizationDetails struct {
	Type           string //
	CredentialType string
	Format         vcsverifiable.Format
	Locations      []string
}

// InitiateIssuanceRequest is the request used by the Issuer to initiate the OIDC VC issuance interaction.
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

// InitiateIssuanceResponse is the response from the Issuer to the Wallet with initiate issuance URL.
type InitiateIssuanceResponse struct {
	InitiateIssuanceURL string
	TxID                TxID
}

type ClientWellKnownConfig struct {
	InitiateIssuanceEndpoint string `json:"initiate_issuance_endpoint"`
}
