/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultTTL = 24 * time.Hour

type Store struct {
	redisClient redis.UniversalClient
}

func NewStore(client redis.UniversalClient) *Store {
	return &Store{
		redisClient: client,
	}
}
