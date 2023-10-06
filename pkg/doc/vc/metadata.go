/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/trustbloc/did-go/doc/util/time"
)

// CredentialMetadata represents the credential metadata.
type CredentialMetadata struct {
	CredentialID   string            `json:"credential"`
	Issuer         string            `json:"issuer,omitempty"`
	CredentialType []string          `json:"credentialType,omitempty"`
	TransactionID  string            `json:"transactionId,omitempty"`
	IssuanceDate   *time.TimeWrapper `json:"issuanceDate,omitempty"`
	ExpirationDate *time.TimeWrapper `json:"expirationDate,omitempty"`
}
