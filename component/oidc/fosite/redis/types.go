/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"encoding/json"
	"time"
)

type genericDocument[T any] struct {
	Record   T         `json:"record"`
	ExpireAt time.Time `json:"expireAt,omitempty"`
}

func (d *genericDocument[T]) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func (d *genericDocument[T]) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}
