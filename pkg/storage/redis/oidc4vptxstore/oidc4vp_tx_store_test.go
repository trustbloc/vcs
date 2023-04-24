/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	redisConnString  = "localhost:6385"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
	defaultClaimsTTL = 3600
	receivedClaimsID = "xyz"

	profileID      = "testProfileID"
	profileVersion = "v1.0"
)

func TestTxStore_Success(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := NewTxStore(client, testutil.DocumentLoader(t), defaultClaimsTTL)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.API().Close(), "failed to close redis client")
	}()

	t.Run("Create tx", func(t *testing.T) {
		id, _, err := store.Create(&presexch.PresentationDefinition{}, profileID, profileVersion)
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create tx then Get by id", func(t *testing.T) {
		id, _, err := store.Create(&presexch.PresentationDefinition{}, profileID, profileVersion)

		require.NoError(t, err)
		require.NotNil(t, id)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
	})

	t.Run("Create tx then update with received claims ID", func(t *testing.T) {
		id, txCreate, err := store.Create(&presexch.PresentationDefinition{ID: "test"}, profileID, profileVersion)

		require.NoError(t, err)
		require.NotNil(t, id)
		require.NotNil(t, txCreate)
		require.Empty(t, txCreate.ReceivedClaimsID)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID:               id,
			ReceivedClaimsID: receivedClaimsID,
		})
		require.NoError(t, err)

		txCreate.ReceivedClaimsID = receivedClaimsID

		txUpdate, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, txUpdate)
		require.Nil(t, txUpdate.ReceivedClaims)
		require.Equal(t, txCreate, txUpdate)
	})
}

func TestTxStore_Fails(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := NewTxStore(client, testutil.DocumentLoader(t), defaultClaimsTTL)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.API().Close(), "failed to close redis client")
	}()

	t.Run("Get empty tx id", func(t *testing.T) {
		_, err := store.Get("")
		require.Contains(t, err.Error(), oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("Get not existing tx id", func(t *testing.T) {
		_, err := store.Get("121212121212121212121212")
		require.EqualError(t, err, oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("test expiration", func(t *testing.T) {
		storeExpired := NewTxStore(client, testutil.DocumentLoader(t), 1)

		id, _, err := storeExpired.Create(&presexch.PresentationDefinition{}, profileID, profileVersion)
		require.NoError(t, err)
		require.NotNil(t, id)

		time.Sleep(2 * time.Second)

		tx, err := storeExpired.Get(id)
		require.Nil(t, tx)
		require.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
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
			"6379/tcp": {{HostIP: "", HostPort: "6385"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
