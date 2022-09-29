/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vptxstore"
)

const (
	mongoDBConnString  = "mongodb://localhost:27021"
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

	store := oidc4vptxstore.NewTxStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create tx", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create tx then find by id", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")

		require.NoError(t, err)
		require.NotNil(t, id)

		tx, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
	})
}

func TestTxStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := oidc4vptxstore.NewTxStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Find invalid tx id", func(t *testing.T) {
		_, err := store.Find("invalid")
		require.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Find empty tx id", func(t *testing.T) {
		_, err := store.Find("")
		require.Contains(t, err.Error(), oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("Find not existing tx id", func(t *testing.T) {
		_, err := store.Find("121212121212121212121212")
		require.EqualError(t, err, oidc4vp.ErrDataNotFound.Error())
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
			"27017/tcp": {{HostIP: "", HostPort: "27021"}},
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
