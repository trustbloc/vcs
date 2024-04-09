/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ciclaimdatastore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	redisapi "github.com/redis/go-redis/v9"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	redisConnString  = "localhost:6384"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
	defaultClaimsTTL = 3600
)

func TestStore(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultClaimsTTL)

	t.Run("test create and get", func(t *testing.T) {
		claims := &oidc4ci.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1},
				EncryptedNonce: []byte{0x2},
			},
		}

		id, err := store.Create(context.Background(), 0, claims)
		assert.NoError(t, err)

		claimsInDB, err := store.GetAndDelete(context.Background(), id)
		assert.NoError(t, err)
		assert.Equal(t, claims, claimsInDB)

		claimsInDB, err = store.GetAndDelete(context.Background(), id)
		assert.Nil(t, claimsInDB)
		assert.Error(t, err)
		assert.ErrorIs(t, err, resterr.ErrDataNotFound)
	})

	t.Run("get non existing document", func(t *testing.T) {
		id := uuid.NewString()

		resp, err := store.GetAndDelete(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, resterr.ErrDataNotFound)
	})

	t.Run("test default expiration", func(t *testing.T) {
		storeExpired := New(client, 0)

		claims := &oidc4ci.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1},
				EncryptedNonce: []byte{0x2},
			},
		}

		id, err := storeExpired.Create(context.Background(), 0, claims)
		assert.NoError(t, err)

		claimsInDB, err := storeExpired.GetAndDelete(context.Background(), id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, resterr.ErrDataNotFound)
	})

	t.Run("test profile expiration", func(t *testing.T) {
		storeExpired := New(client, 1000)

		claims := &oidc4ci.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1},
				EncryptedNonce: []byte{0x2},
			},
		}

		id, err := storeExpired.Create(context.Background(), 1, claims)
		assert.NoError(t, err)

		time.Sleep(time.Second)

		claimsInDB, err := storeExpired.GetAndDelete(context.Background(), id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, resterr.ErrDataNotFound)
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
			"6379/tcp": {{HostIP: "", HostPort: "6384"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
