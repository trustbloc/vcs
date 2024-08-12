/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cinoncestore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

type redisDocument struct {
	ID              string
	ExpireAt        time.Time
	TransactionData *issuecredential.TransactionData
}

func (d *redisDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *redisDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
