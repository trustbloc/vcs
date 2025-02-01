/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistatestore

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	redisConnString   = "localhost:6383"
	dockerRedisImage  = "redis"
	dockerRedisTag    = "alpine3.17"
	defaultExpiration = 3600
)

func TestStore(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultExpiration)

	t.Run("try insert duplicate op_state", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.AuthorizeState{}

		err1 := store.SaveAuthorizeState(context.Background(), 0, id, toInsert)
		assert.NoError(t, err1)

		err2 := store.SaveAuthorizeState(context.Background(), 0, id, toInsert)
		assert.ErrorIs(t, err2, ErrOpStateKeyDuplication)
	})

	t.Run("test default expiration", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.AuthorizeState{}

		expiredStore := New(client, -1)

		err1 := expiredStore.SaveAuthorizeState(context.Background(), 0, id, toInsert)
		assert.NoError(t, err1)

		resp2, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
	})

	t.Run("test profile expiration", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.AuthorizeState{}

		expiredStore := New(client, 100)

		err1 := expiredStore.SaveAuthorizeState(context.Background(), 1, id, toInsert)
		assert.NoError(t, err1)

		time.Sleep(time.Second)

		resp2, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
	})

	t.Run("test insert and find", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.AuthorizeState{
			RespondMode: "random",
		}

		err1 := store.SaveAuthorizeState(context.Background(), 0, id, toInsert)
		assert.NoError(t, err1)

		resp2, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.NoError(t, err2)
		assert.Equal(t, toInsert, resp2)
	})

	t.Run("find non existing document", func(t *testing.T) {
		id := uuid.New().String()

		resp, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
	})
}

func TestWithTimeouts(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultExpiration)

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	t.Run("Create timeout", func(t *testing.T) {
		err = store.SaveAuthorizeState(ctx, 0, uuid.NewString(), &oidc4ci.AuthorizeState{})
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.GetAuthorizeState(ctx, "111")
		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
}

func waitForRedisToBeUp() error {
	return backoff.Retry(pingRedis, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingRedis() error {
	rdb := redisapi.NewClient(&redisapi.Options{
		Addr: redisConnString,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return rdb.Ping(ctx).Err()
}

func startRedisContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	redisResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerRedisImage,
		Tag:        dockerRedisTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"6379/tcp": {{HostIP: "", HostPort: "6383"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
