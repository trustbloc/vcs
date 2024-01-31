/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cinoncestore

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	redisConnString  = "localhost:6380"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
	defaultTTL       = 3600
)

func TestStore(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultTTL)

	t.Run("try insert duplicate op_state", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.TransactionData{
			OpState: id,
		}

		resp1, err1 := store.Create(context.Background(), toInsert)
		assert.NoError(t, err1)
		assert.NotEmpty(t, resp1)

		resp2, err2 := store.Create(context.Background(), toInsert)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
		assert.Empty(t, resp2)
	})

	t.Run("test expiration", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.TransactionData{
			OpState: id,
		}

		resp1, err1 := store.Create(context.Background(), toInsert, oidc4ci.WithDocumentTTL(-1*time.Second))
		assert.NoError(t, err1)
		assert.NotNil(t, resp1)

		resp2, err2 := store.FindByOpState(context.Background(), toInsert.OpState)
		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
	})

	t.Run("test insert and find", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4ci.TransactionData{
			CredentialTemplate: &profileapi.CredentialTemplate{
				Contexts:          []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1"},
				ID:                "templateID",
				Type:              "PermanentResidentCard",
				CredentialSubject: []byte(`{"sub_1":"abcd"}`),
			},
			ProfileID:                          "profileID",
			CredentialFormat:                   vcsverifiable.Ldp,
			OIDCCredentialFormat:               vcsverifiable.JwtVCJsonLD,
			AuthorizationEndpoint:              "authEndpoint",
			PushedAuthorizationRequestEndpoint: "pushedAuth",
			TokenEndpoint:                      "tokenEndpoint",
			ClaimEndpoint:                      "432",
			GrantType:                          "342",
			ResponseType:                       "123",
			Scope:                              []string{"213", "321"},
			AuthorizationDetails: &oidc4ci.AuthorizationDetails{
				Type:                      "321",
				CredentialConfigurationID: "CredentialConfigurationID",
				CredentialDefinition: &oidc4ci.CredentialDefinition{
					Type: []string{"fdsfsd"},
				},
				Format:    "vxcxzcz",
				Locations: []string{"loc1", "loc2"},
			},
			IssuerAuthCode: uuid.NewString(),
			IssuerToken:    uuid.NewString(),
			OpState:        id,
			UserPin:        "321",
			IsPreAuthFlow:  true,
			PreAuthCode:    uuid.NewString(),
			WebHookURL:     "http://remote-url",
			DID:            "did:123",
			ClaimDataID:    uuid.NewString(),
		}

		var resp *oidc4ci.Transaction

		resp, err = store.Create(context.Background(), toInsert)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		txID := resp.ID

		resp, err = store.Get(context.Background(), txID)
		assert.NoError(t, err)
		assert.Equal(t, txID, resp.ID)
		assert.Equal(t, *toInsert, resp.TransactionData)

		resp, err = store.FindByOpState(context.Background(), toInsert.OpState)
		assert.NoError(t, err)
		assert.Equal(t, txID, resp.ID)
		assert.Equal(t, *toInsert, resp.TransactionData)
	})

	t.Run("test update", func(t *testing.T) {
		id := uuid.NewString()

		toInsert := &oidc4ci.TransactionData{
			CredentialTemplate:   nil,
			CredentialFormat:     vcsverifiable.Jwt,
			ClaimEndpoint:        "432",
			GrantType:            "342",
			ResponseType:         "123",
			Scope:                []string{"213", "321"},
			AuthorizationDetails: &oidc4ci.AuthorizationDetails{Type: "321"},
			OpState:              id,
		}

		resp, createErr := store.Create(context.TODO(), toInsert)
		if createErr != nil {
			assert.NoError(t, createErr)
		}

		assert.NoError(t, err)

		resp.ClaimEndpoint = "test_endpoint"

		assert.NoError(t, store.Update(context.TODO(), resp))

		found, err2 := store.FindByOpState(context.TODO(), id)
		assert.NoError(t, err2)
		assert.Equal(t, resp.ClaimEndpoint, found.ClaimEndpoint)

		found, err2 = store.Get(context.TODO(), found.ID)
		assert.NoError(t, err2)
		assert.Equal(t, resp.ClaimEndpoint, found.ClaimEndpoint)
	})

	t.Run("find non existing document", func(t *testing.T) {
		id := uuid.New().String()

		resp, err2 := store.FindByOpState(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err2, resterr.ErrDataNotFound)
	})
}

func TestWithTimeouts(t *testing.T) {
	pool, redisResource := startRedisContainer(t)
	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	store := New(client, defaultTTL)

	defer func() {
		require.NoError(t, client.API().Close(), "failed to close redis client")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	t.Run("Create timeout", func(t *testing.T) {
		resp, err := store.Create(ctx, &oidc4ci.TransactionData{})

		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.FindByOpState(ctx, "111")

		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
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
			"6379/tcp": {{HostIP: "", HostPort: "6380"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
