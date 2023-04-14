/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidcnoncestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/redis"
	"github.com/trustbloc/vcs/pkg/storage/redis/oidcnoncestore"
)

const (
	redisConnString  = "localhost:6382"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
)

func TestTxStore_Success(t *testing.T) {
	pool, mongoDBResource := startRedisContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := oidcnoncestore.New(client)

	t.Run("Set not exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key", "value", 10*time.Second)
		require.NoError(t, err)
		require.True(t, isSet)
	})

	t.Run("Set exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key2", "value", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		isSet, err = store.SetIfNotExist("key2", "txID", 10*time.Second)
		require.False(t, isSet)
		require.NoError(t, err)
	})

	t.Run("Get not exist", func(t *testing.T) {
		_, exists, err := store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
	})

	t.Run("Get exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", "txID", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, oidc4vp.TxID("txID"), data)
	})

	t.Run("Get exist and check if deleted", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", "txID", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, oidc4vp.TxID("txID"), data)

		_, exists, err = store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
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
			"6379/tcp": {{HostIP: "", HostPort: "6382"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
