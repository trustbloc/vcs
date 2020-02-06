/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CreateCredentialRequest input data for edge service issuer rest api
type CreateCredentialRequest struct {
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
	Profile string             `json:"profile,omitempty"`
}

// StoreVCRequest stores the credential with profile name
type StoreVCRequest struct {
	Profile    string `json:"profile"`
	Credential string `json:"credential"`
}

// ProfileRequest struct the input for creating profile
type ProfileRequest struct {
	Name          string `json:"name"`
	URI           string `json:"uri"`
	SignatureType string `json:"signatureType"`
	Creator       string `json:"creator"`
}

// ProfileResponse struct the output for creating profile
type ProfileResponse struct {
	Name          string     `json:"name"`
	DID           string     `json:"did"`
	URI           string     `json:"uri"`
	SignatureType string     `json:"signatureType"`
	Creator       string     `json:"creator"`
	Created       *time.Time `json:"created"`
}

// VerifyCredentialResponse describes verify credential response
type VerifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}
