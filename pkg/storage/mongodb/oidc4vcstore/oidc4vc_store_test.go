/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vcstore

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27024"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, err)

	store, err := New(context.Background(), client)

	assert.NoError(t, err)

	t.Run("try insert duplicate op_state", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4vc.TransactionData{
			OpState: id,
		}

		resp1, err1 := store.Create(context.Background(), toInsert)
		assert.NoError(t, err1)
		assert.NotEmpty(t, resp1)

		resp2, err2 := store.Create(context.Background(), toInsert)
		assert.ErrorIs(t, err2, oidc4vc.ErrDataNotFound)
		assert.Empty(t, resp2)
	})

	t.Run("test expiration", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4vc.TransactionData{
			OpState: id,
		}

		resp1, err1 := store.Create(context.Background(), toInsert, oidc4vc.WithDocumentTTL(-1*time.Second))
		assert.NoError(t, err1)
		assert.NotNil(t, resp1)

		resp2, err2 := store.FindByOpState(context.Background(), toInsert.OpState)
		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, oidc4vc.ErrDataNotFound)
	})

	t.Run("test insert and find", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &oidc4vc.TransactionData{
			CredentialTemplate: &profileapi.CredentialTemplate{
				Contexts:          []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/citizenship/v1"},
				ID:                "templateID",
				Type:              "PermanentResidentCard",
				Issuer:            "test_issuer",
				CredentialSubject: []byte(`{"sub_1" : "abcd"}`),
			},
			ProfileID:                          "profileID",
			CredentialFormat:                   vcsverifiable.Ldp,
			AuthorizationEndpoint:              "authEndpoint",
			PushedAuthorizationRequestEndpoint: "pushedAuth",
			TokenEndpoint:                      "tokenEndpoint",
			ClaimEndpoint:                      "432",
			ClientID:                           "321",
			ClientSecret:                       "secret",
			GrantType:                          "342",
			ResponseType:                       "123",
			Scope:                              []string{"213", "321"},
			AuthorizationDetails: &oidc4vc.AuthorizationDetails{
				Type:           "321",
				CredentialType: "fdsfsd",
				Format:         "vxcxzcz",
				Locations:      []string{"loc1", "loc2"},
			},
			IssuerAuthCode:  uuid.NewString(),
			IssuerToken:     uuid.NewString(),
			OpState:         id,
			UserPinRequired: true,
			IsPreAuthFlow:   true,
			PreAuthCode:     uuid.NewString(),
			ClaimData: map[string]interface{}{
				"abcd": "awesome",
			},
		}

		var resp *oidc4vc.Transaction

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

	t.Run("create multiple instances", func(t *testing.T) {
		wg := sync.WaitGroup{}

		for i := 0; i < 2; i++ {
			wg.Add(1)

			go func() {
				defer wg.Done()
				srv, err2 := New(context.Background(), client)
				assert.NoError(t, err2)
				assert.NotNil(t, srv)
			}()
		}

		wg.Wait()
	})

	t.Run("test update", func(t *testing.T) {
		id := uuid.NewString()

		toInsert := &oidc4vc.TransactionData{
			CredentialTemplate:   nil,
			CredentialFormat:     vcsverifiable.Jwt,
			ClaimEndpoint:        "432",
			GrantType:            "342",
			ResponseType:         "123",
			Scope:                []string{"213", "321"},
			AuthorizationDetails: &oidc4vc.AuthorizationDetails{Type: "321"},
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
	})

	t.Run("find non existing document", func(t *testing.T) {
		id := uuid.New().String()

		resp, err2 := store.FindByOpState(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err2, oidc4vc.ErrDataNotFound)
	})

	t.Run("get by invalid tx id", func(t *testing.T) {
		resp, err2 := store.Get(context.Background(), "")
		assert.Nil(t, resp)
		assert.Error(t, err2)
	})
}

func TestWithTimeouts(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", 1)
	assert.NoError(t, err)

	store, err := New(context.Background(), client)

	assert.NoError(t, err)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	t.Run("Create timeout", func(t *testing.T) {
		resp, err := store.Create(ctx, &oidc4vc.TransactionData{})

		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.FindByOpState(ctx, "111")

		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Update InvalidKey", func(t *testing.T) {
		err := store.Update(context.TODO(), &oidc4vc.Transaction{ID: "1"})
		assert.ErrorContains(t, err, "the provided hex string is not a valid ObjectID")
	})
}

func TestMigrate(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", 1)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := New(ctx, client)
	assert.Nil(t, store)
	assert.ErrorContains(t, err, "context canceled")

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27024"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB() error {
	var err error

	tM := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistryBuilder().RegisterTypeMapEntry(bsontype.EmbeddedDocument, tM).Build()
	clientOpts := options.Client().SetRegistry(reg).ApplyURI(mongoDBConnString)

	mongoClient, err := mongo.NewClient(clientOpts)
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	db := mongoClient.Database("test")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}
