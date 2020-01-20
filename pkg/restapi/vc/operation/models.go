/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CreateCrendentialRequest input data for edge service issuer rest api
type CreateCrendentialRequest struct {
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
	Profile string             `json:"profile,omitempty"`
}

// CreateCrendentialResponse returns the credential with an ID
type CreateCrendentialResponse struct {
	ID string `json:"id"`
	CreateCrendentialRequest
}

// ProfileRequest struct the input for creating profile
type ProfileRequest struct {
	Name          string `json:"name"`
	DID           string `json:"did"`
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
