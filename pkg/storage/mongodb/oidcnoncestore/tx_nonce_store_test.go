/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidcnoncestore_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidcnoncestore"
)

const (
	mongoDBConnString  = "mongodb://localhost:27023"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestTxStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store, err := oidcnoncestore.New(client)
	assert.NoError(t, err)

	t.Run("Set not exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key", "value", 10*time.Second)
		require.NoError(t, err)
		require.True(t, isSet)
	})

	t.Run("Set exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key2", "value", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		isSet, err = store.SetIfNotExist("key2", "txID", 10*time.Second)
		require.False(t, isSet)
		require.NoError(t, err)
	})

	t.Run("Get not exist", func(t *testing.T) {
		_, exists, err := store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
	})

	t.Run("Get exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", "txID", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, oidc4vp.TxID("txID"), data)
	})

	t.Run("Get exist and check if deleted", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", "txID", 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, oidc4vp.TxID("txID"), data)

		_, exists, err = store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
	})
}

func TestTxStore_ConnectoinFail(t *testing.T) {
	client, err := mongodb.New(mongoDBConnString, "testdb", 0)
	require.NoError(t, err)

	t.Run("Set fail", func(t *testing.T) {
		_, err = oidcnoncestore.New(client)
		require.Contains(t, err.Error(), "context deadline exceeded")
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
			"27017/tcp": {{HostIP: "", HostPort: "27023"}},
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
