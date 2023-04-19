/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistatestore

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

type redisDocument struct {
	ExpireAt time.Time               `json:"expireAt"`
	State    *oidc4ci.AuthorizeState `json:"state"`
}

func (d *redisDocument) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *redisDocument) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
