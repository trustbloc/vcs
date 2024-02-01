/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vci

import (
	"time"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type ProofClaims struct {
	Issuer   string `json:"iss,omitempty" cbor:"1,keyasint"`
	Audience string `json:"aud,omitempty" cbor:"3,keyasint"`
	IssuedAt *int64 `json:"iat,omitempty" cbor:"6,keyasint"`
	Nonce    string `json:"nonce,omitempty" cbor:"10,keyasint"`
}

type CredentialRequest struct {
	Format verifiable.OIDCFormat `json:"format,omitempty"`
	Types  []string              `json:"types"`
	Proof  Proof              `json:"proof,omitempty"`
}

type Proof struct {
	JWT       string `json:"jwt"`
	CWT       string `json:"cwt"`
	ProofType string `json:"proof_type"`
}

type CredentialResponse struct {
	AcceptanceToken string                `json:"acceptance_token,omitempty"`
	CNonce          string                `json:"c_nonce,omitempty"`
	CNonceExpiresIn int                   `json:"c_nonce_expires_in,omitempty"`
	Credential      interface{}           `json:"credential"`
	Format          verifiable.OIDCFormat `json:"format"`
	AckID           *string               `json:"ack_id"`
}

type PerfInfo struct {
	GetIssuerCredentialsOIDCConfig time.Duration `json:"vci_get_issuer_credentials_oidc_config"`
	GetAccessToken                 time.Duration `json:"vci_get_access_token"`
	GetCredential                  time.Duration `json:"vci_get_credential"`
	CredentialsAck                 time.Duration `json:"vci_credentials_ack"`
}
