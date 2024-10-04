/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

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
	"github.com/trustbloc/vc-go/presexch"

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
	customScope    = "customScope"
)

func TestTxStore_Success(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, e := redis.New([]string{redisConnString})
	assert.NoError(t, e)

	store := NewTxStore(client, testutil.DocumentLoader(t), defaultClaimsTTL)
	assert.NotNil(t, store)

	defer func() {
		assert.NoError(t, client.API().Close(), "failed to close redis client")
	}()

	t.Run("Success: create tx, update with received claims ID, and delete", func(t *testing.T) {
		id, txCreate, err := store.Create(
			&presexch.PresentationDefinition{ID: "test"}, profileID, profileVersion, 0, []string{customScope})
		assert.NoError(t, err)

		assert.NotNil(t, id)
		assert.NotNil(t, txCreate)
		assert.Empty(t, txCreate.ReceivedClaimsID)
		assert.Equal(t, []string{customScope}, txCreate.CustomScopes)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID:               id,
			ReceivedClaimsID: receivedClaimsID,
		}, 0)
		assert.NoError(t, err)

		txCreate.ReceivedClaimsID = receivedClaimsID

		txUpdate, err := store.Get(id)
		assert.NoError(t, err)

		assert.Nil(t, txUpdate.ReceivedClaims)
		assert.Equal(t, txCreate, txUpdate)

		err = store.Delete(id)
		assert.NoError(t, err)

		_, err = store.Get(id)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)

		// Delete not existing tx.
		err = store.Delete(id)
		assert.NoError(t, err)
	})

	t.Run("Success: default expiration", func(t *testing.T) {
		storeExpired := NewTxStore(client, testutil.DocumentLoader(t), 1)

		id, _, err := storeExpired.Create(
			&presexch.PresentationDefinition{}, profileID, profileVersion, 0, []string{customScope})
		assert.NoError(t, err)
		assert.NotNil(t, id)

		time.Sleep(time.Second)

		tx, err := storeExpired.Get(id)
		assert.Nil(t, tx)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("Success: profile expiration", func(t *testing.T) {
		id, _, err := store.Create(
			&presexch.PresentationDefinition{}, profileID, profileVersion, 1, []string{customScope})
		assert.NoError(t, err)
		assert.NotNil(t, id)

		time.Sleep(time.Second)

		tx, err := store.Get(id)
		assert.Nil(t, tx)
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
	assert.NoError(t, err)

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
