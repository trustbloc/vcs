/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpnoncestore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

type nonceDocument struct {
	TxID     oidc4vp.TxID `json:"txId"`
	ExpireAt time.Time    `json:"expireAt"`
}

func (d *nonceDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *nonceDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
