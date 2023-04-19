/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	redischeck "github.com/trustbloc/vcs/pkg/observability/health/redis"
)

const (
	redisConnString  = "localhost:6387"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
)

func TestSuccess(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	})

	err := redischeck.New([]string{redisConnString},
		redischeck.WithMasterName(""),
		redischeck.WithPassword(""),
		redischeck.WithTLSConfig(nil),
	)(context.Background())

	require.NoError(t, err)
}

func TestFailToPingRedis(t *testing.T) {
	errCh := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		errCh <- redischeck.New([]string{redisConnString})(ctx)
	}()

	cancel()

	require.ErrorContains(t, <-errCh, "failed to ping redis")
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
			"6379/tcp": {{HostIP: "", HostPort: "6387"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
