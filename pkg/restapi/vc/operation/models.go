/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// CreateCrendential input data for edge service issuer rest api
type CreateCrendential struct {
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
}

// ProfileRequest struct the input for creating profile
type ProfileRequest struct {
	DID string `json:"did"`
	URI string `json:"uri"`
}

// ProfileResponse struct the output for creating profile
type ProfileResponse struct {
	ID        string     `json:"id"`
	URI       string     `json:"uri"`
	IssueDate *time.Time `json:"issueDate"`
	DID       string     `json:"did"`
}

// VerifyCredentialResponse describes verify credential response
type VerifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}
