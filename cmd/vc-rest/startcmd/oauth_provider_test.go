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
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestBoostrapOidc(t *testing.T) {
	secret := uuid.NewString()

	oauthClient := oauth2client.Client{
		ID:            "id",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://example.com/redirect"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
	}

	t.Run("mongo", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)
		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		mongoClient, clientErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
		assert.NoError(t, clientErr)

		t.Run("success", func(t *testing.T) {
			provider, manager, err := bootstrapOAuthProvider(
				context.TODO(), secret, "", mongoClient, nil, []oauth2client.Client{oauthClient})
			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.NotNil(t, manager)
		})

		t.Run("success with duplicate oauth clients", func(t *testing.T) {
			oauthClients := []oauth2client.Client{
				oauthClient,
				{ID: oauthClient.ID},
			}

			provider, manager, err := bootstrapOAuthProvider(
				context.TODO(), secret, "", mongoClient, nil, oauthClients)
			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.NotNil(t, manager)
		})
	})

	t.Run("redis", func(t *testing.T) {
		pool, redisResource := startRedisContainer(t)
		defer func() {
			assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
		}()

		redisClient, err := redis.New([]string{redisConnString})
		assert.NoError(t, err)

		t.Run("success", func(t *testing.T) {
			provider, manager, err := bootstrapOAuthProvider(
				context.TODO(), secret, redisStore, nil, redisClient, []oauth2client.Client{oauthClient})
			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.NotNil(t, manager)
		})

		t.Run("success with duplicate oauth clients", func(t *testing.T) {
			oauthClients := []oauth2client.Client{
				oauthClient,
				{ID: oauthClient.ID},
			}

			provider, manager, err := bootstrapOAuthProvider(
				context.TODO(), secret, redisStore, nil, redisClient, oauthClients)
			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.NotNil(t, manager)
		})
	})
}

func TestBoostrapWithInvalidSecret(t *testing.T) {
	provider, manager, err := bootstrapOAuthProvider(
		context.TODO(), "", "", nil, nil, []oauth2client.Client{})
	assert.Nil(t, provider)
	assert.Nil(t, manager)
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

	provider, manager, err := bootstrapOAuthProvider(ctx, secret, "", client, nil, []oauth2client.Client{})

	assert.Nil(t, provider)
	assert.Nil(t, manager)
	assert.ErrorContains(t, err, "context canceled")
}
