/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpclaimsstore

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	redisConnString  = "localhost:6381"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
	defaultClaimsTTL = 3600
)

func TestStore(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultClaimsTTL)

	t.Run("test create and get, followed by delete - JWT", func(t *testing.T) {
		receivedClaims := &oidc4vp.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1, 0x2},
				EncryptedNonce: []byte{0x3},
			},
		}

		id, err := store.Create(receivedClaims, 0)
		assert.NoError(t, err)

		claimsInDB, err := store.Get(id)
		assert.NoError(t, err)
		require.NotNil(t, claimsInDB)

		require.Equal(t, *receivedClaims, *claimsInDB)

		err = store.Delete(id)
		require.NoError(t, err)

		claimsInDB, err = store.Get(id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("get non existing document", func(t *testing.T) {
		id := uuid.NewString()

		resp, err := store.Get(id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("test default expiration", func(t *testing.T) {
		storeExpired := New(client, 1)

		receivedClaims := &oidc4vp.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1, 0x2},
				EncryptedNonce: []byte{0x3},
			},
		}

		id, err := storeExpired.Create(receivedClaims, 0)
		require.NoError(t, err)

		time.Sleep(time.Second)

		claimsInDB, err := storeExpired.Get(id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("test profile expiration", func(t *testing.T) {
		storeExpired := New(client, 100)

		receivedClaims := &oidc4vp.ClaimData{
			EncryptedData: &dataprotect.EncryptedData{
				Encrypted:      []byte{0x1, 0x2},
				EncryptedNonce: []byte{0x3},
			},
		}

		id, err := storeExpired.Create(receivedClaims, 1)
		require.NoError(t, err)

		time.Sleep(time.Second)

		claimsInDB, err := storeExpired.Get(id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
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
			"6379/tcp": {{HostIP: "", HostPort: "6381"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
