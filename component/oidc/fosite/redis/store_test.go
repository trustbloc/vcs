/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"

	"github.com/pborman/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

func TestStoreFail(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client := redis.NewClient(&redis.Options{
		Addr:                  redisConnString,
		ContextTimeoutEnabled: true,
	})

	s := NewStore(client)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	_, err := s.InsertClient(ctx, dto.Client{
		ID:     uuid.New(),
		Scopes: []string{"awesome"},
	})

	assert.ErrorContains(t, err, "context canceled")
}
