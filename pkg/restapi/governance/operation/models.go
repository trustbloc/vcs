/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

// GovernanceProfileRequest governance mode profile request
type GovernanceProfileRequest struct {
	Name                    string                             `json:"name"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	DID                     string                             `json:"did"`
	DIDPrivateKey           string                             `json:"didPrivateKey"`
	DIDKeyType              string                             `json:"didKeyType"`
	DIDKeyID                string                             `json:"didKeyID"`
	UNIRegistrar            model.UNIRegistrar                 `json:"uniRegistrar,omitempty"`
}

// IssueCredentialRequest request for issuing credential.
type IssueCredentialRequest struct {
	DID string `json:"did,omitempty"`
}
