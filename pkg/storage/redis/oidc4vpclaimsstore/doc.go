/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpclaimsstore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

type claimDataDocument struct {
	ExpireAt time.Time `json:"expireAt"`
	*oidc4vp.ClaimData
}

func (d *claimDataDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *claimDataDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
