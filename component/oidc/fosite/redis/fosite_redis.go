/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"time"

	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const defaultTTL = 24 * time.Hour

type Store struct {
	redisClient *redis.Client
}

func NewStore(client *redis.Client) *Store {
	return &Store{
		redisClient: client,
	}
}
