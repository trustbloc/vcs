/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ciclaimdatastore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

type redisDocument struct {
	ClaimData issuecredential.ClaimData `json:"claimData"`
	ExpireAt  time.Time                 `json:"expireAt,omitempty"`
}

func (d *redisDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *redisDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
