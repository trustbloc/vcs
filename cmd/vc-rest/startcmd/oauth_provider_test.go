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
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fositedto "github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestBoostrapOidc(t *testing.T) {
	secret := uuid.NewString()

	oauthClient := fositedto.Client{
		ID:            "id",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://example.com/redirect"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Public:        true,
	}

	t.Run("mongo", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)
		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		mongoClient, clientErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
		assert.NoError(t, clientErr)

		t.Run("success", func(t *testing.T) {
			provider, err := bootstrapOAuthProvider(
				context.TODO(), secret, "", mongoClient, nil, []fositedto.Client{oauthClient})
			assert.NoError(t, err)
			assert.NotNil(t, provider)
		})

		t.Run("success with duplicate oauth clients", func(t *testing.T) {
			oauthClients := []fositedto.Client{
				oauthClient,
				{ID: oauthClient.ID},
			}

			provider, err := bootstrapOAuthProvider(
				context.TODO(), secret, "", mongoClient, nil, oauthClients)
			assert.NoError(t, err)
			assert.NotNil(t, provider)
		})
	})

	t.Run("redis", func(t *testing.T) {
		pool, redisResource := startRedisContainer(t)
		defer func() {
			assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
		}()

		redisClient := redis.NewClient(&redis.Options{
			Addr:                  redisConnString,
			ContextTimeoutEnabled: true,
		})

		t.Run("success", func(t *testing.T) {
			provider, err := bootstrapOAuthProvider(
				context.TODO(), secret, redisOAuthStore, nil, redisClient, []fositedto.Client{oauthClient})
			assert.NoError(t, err)
			assert.NotNil(t, provider)
		})

		t.Run("success with duplicate oauth clients", func(t *testing.T) {
			oauthClients := []fositedto.Client{
				oauthClient,
				{ID: oauthClient.ID},
			}

			provider, err := bootstrapOAuthProvider(
				context.TODO(), secret, redisOAuthStore, nil, redisClient, oauthClients)
			assert.NoError(t, err)
			assert.NotNil(t, provider)
		})
	})
}

func TestBoostrapWithInvalidSecret(t *testing.T) {
	provider, err := bootstrapOAuthProvider(
		context.TODO(), "", "", nil, nil, []fositedto.Client{})
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

	provider, err := bootstrapOAuthProvider(ctx, secret, "", client, nil, []fositedto.Client{})

	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "context canceled")
}
