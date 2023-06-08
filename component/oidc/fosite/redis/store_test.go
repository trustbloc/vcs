/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestStoreFail(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	s := NewStore(client)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	_, err = s.InsertClient(ctx, &oauth2client.Client{
		ID:     uuid.New(),
		Scopes: []string{"awesome"},
	})

	assert.ErrorContains(t, err, "context canceled")
}
