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

	"github.com/trustbloc/vcs/component/oidc/fositemongo"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestBoostrapOidc(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, clientErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, clientErr)

	secret := uuid.NewString()

	oauthClient := fositemongo.Client{
		ID:            "id",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://example.com/redirect"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Public:        true,
	}

	t.Run("success", func(t *testing.T) {
		provider, err := bootstrapOAuthProvider(context.TODO(), secret, client, []fositemongo.Client{oauthClient})
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("success with duplicate oauth clients", func(t *testing.T) {
		oauthClients := []fositemongo.Client{
			oauthClient,
			{ID: oauthClient.ID},
		}

		provider, err := bootstrapOAuthProvider(context.TODO(), secret, client, oauthClients)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})
}

func TestBoostrapWithInvalidSecret(t *testing.T) {
	provider, err := bootstrapOAuthProvider(context.TODO(), "", nil, []fositemongo.Client{})
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

	provider, err := bootstrapOAuthProvider(ctx, secret, client, []fositemongo.Client{})

	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "context canceled")
}
