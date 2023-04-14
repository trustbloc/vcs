/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const (
	redisConnString  = "localhost:6379"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
)

func TestClient(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	t.Run("OK", func(t *testing.T) {
		client, err := New([]string{redisConnString})
		require.NoError(t, err)
		require.NotNil(t, client)

		require.NoError(t, client.API().Close())
	})

	t.Run("Timeout", func(t *testing.T) {
		client, err := New([]string{redisConnString}, WithTimeout(0))

		require.Nil(t, client)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context deadline exceeded")
	})
}

func waitForRedisToBeUp() error {
	return backoff.Retry(pingRedis, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingRedis() error {
	rdb := redis.NewClient(&redis.Options{
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
			"6379/tcp": {{HostIP: "", HostPort: "6379"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
