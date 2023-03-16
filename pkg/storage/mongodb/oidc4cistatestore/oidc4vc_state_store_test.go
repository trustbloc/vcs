/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistatestore

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

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27027"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, err)

	store, err := New(context.Background(), client)

	assert.NoError(t, err)

	t.Run("try insert duplicate op_state", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &AuthorizeState{}

		err1 := store.SaveAuthorizeState(context.Background(), id, toInsert)
		assert.NoError(t, err1)

		err2 := store.SaveAuthorizeState(context.Background(), id, toInsert)
		assert.ErrorContains(t, err2, "duplicate key error collection")
	})

	t.Run("test expiration", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &AuthorizeState{}

		err1 := store.SaveAuthorizeState(context.Background(), id, toInsert,
			oidc4ci.WithDocumentTTL(-2*time.Second))
		assert.NoError(t, err1)

		resp2, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, oidc4ci.ErrDataNotFound)
	})

	t.Run("test insert and find", func(t *testing.T) {
		id := uuid.New().String()

		toInsert := &AuthorizeState{
			RespondMode: "random",
		}

		err1 := store.SaveAuthorizeState(context.Background(), id, toInsert)
		assert.NoError(t, err1)

		resp2, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.NoError(t, err2)
		assert.Equal(t, toInsert, resp2)
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

	t.Run("find non existing document", func(t *testing.T) {
		id := uuid.New().String()

		resp, err2 := store.GetAuthorizeState(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err2, oidc4ci.ErrDataNotFound)
	})
}

func TestWithTimeouts(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", mongodb.WithTimeout(time.Second*1))
	assert.NoError(t, err)

	store, err := New(context.Background(), client)

	assert.NoError(t, err)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	t.Run("Create timeout", func(t *testing.T) {
		err := store.SaveAuthorizeState(ctx, uuid.NewString(), &AuthorizeState{})
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.GetAuthorizeState(ctx, "111")
		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27027"}},
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
