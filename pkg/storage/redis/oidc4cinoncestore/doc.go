/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cinoncestore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

type redisDocument struct {
	ID              string
	ExpireAt        time.Time
	TransactionData *oidc4ci.TransactionData
}

func (d *redisDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *redisDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
