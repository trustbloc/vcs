/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestBoostrapOidc(t *testing.T) {
	secret := uuid.NewString()

	oauthClient := &oauth2client.Client{
		ID:            "id",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://example.com/redirect"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
	}

	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	mongoClient, clientErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, clientErr)

	clientManager, storeErr := clientmanager.NewStore(context.Background(), mongoClient)
	assert.NoError(t, storeErr)

	_, insertErr := clientManager.InsertClient(context.Background(), oauthClient)
	assert.NoError(t, insertErr)

	redisPool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, redisPool.Purge(redisResource), "failed to purge Redis resource")
	}()

	redisClient, redisErr := redis.New([]string{redisConnString})
	assert.NoError(t, redisErr)

	t.Run("mongo success", func(t *testing.T) {
		provider, err := bootstrapOAuthProvider(context.Background(), secret, "", mongoClient, nil, clientManager)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("redis success", func(t *testing.T) {
		provider, err := bootstrapOAuthProvider(
			context.Background(), secret, redisStore, nil, redisClient, clientManager)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})
}

func TestBoostrapWithInvalidSecret(t *testing.T) {
	provider, err := bootstrapOAuthProvider(context.TODO(), "", "", nil, nil, nil)
	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "invalid secret")
}

func TestBoostrapOidcWithExpiredContext(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, err)

	secret := uuid.NewString()

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	provider, err := bootstrapOAuthProvider(ctx, secret, "", client, nil, nil)

	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "context canceled")
}
