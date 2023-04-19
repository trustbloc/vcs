/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
)

type txDocument struct {
	ProfileID              string                           `json:"profileId"`
	ReceivedClaimsID       string                           `json:"receivedClaimsId,omitempty"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentationDefinition"`
	ExpireAt               time.Time                        `json:"expireAt"`
}

func (d *txDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *txDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
