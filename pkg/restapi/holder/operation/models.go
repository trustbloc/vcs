/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

// HolderProfileRequest holder mode profile request
type HolderProfileRequest struct {
	Name                    string                             `json:"name"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	DID                     string                             `json:"did"`
	DIDPrivateKey           string                             `json:"didPrivateKey"`
	DIDKeyType              string                             `json:"didKeyType"`
	DIDKeyID                string                             `json:"didKeyID"`
	UNIRegistrar            model.UNIRegistrar                 `json:"uniRegistrar,omitempty"`
	OverwriteHolder         bool                               `json:"overwriteHolder,omitempty"`
}

// SignPresentationRequest request for signing a presentation.
type SignPresentationRequest struct {
	Presentation json.RawMessage          `json:"presentation,omitempty"`
	Opts         *SignPresentationOptions `json:"options,omitempty"`
}

// SignPresentationOptions options for signing a presentation.
type SignPresentationOptions struct {
	VerificationMethod string     `json:"verificationMethod,omitempty"`
	AssertionMethod    string     `json:"assertionMethod,omitempty"`
	ProofPurpose       string     `json:"proofPurpose,omitempty"`
	Created            *time.Time `json:"created,omitempty"`
	Challenge          string     `json:"challenge,omitempty"`
	Domain             string     `json:"domain,omitempty"`
}
