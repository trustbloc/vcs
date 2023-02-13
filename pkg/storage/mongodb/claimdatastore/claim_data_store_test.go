/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package claimdatastore

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
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27031"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
	defaultClaimsTTL   = 3600
)

func TestStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, createErr := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, createErr)

	store, createErr := New(context.Background(), client, defaultClaimsTTL)
	assert.NoError(t, createErr)

	t.Run("test create and get", func(t *testing.T) {
		claims := &oidc4ci.ClaimData{
			"claim1": "value1",
			"claim2": "value2",
		}

		id, err := store.Create(context.Background(), claims)
		assert.NoError(t, err)

		claimsInDB, err := store.GetAndDelete(context.Background(), id)
		assert.NoError(t, err)
		assert.Equal(t, claims, claimsInDB)
	})

	t.Run("get non existing document", func(t *testing.T) {
		id := primitive.NewObjectID().Hex()

		resp, err := store.GetAndDelete(context.Background(), id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, oidc4ci.ErrDataNotFound)
	})

	t.Run("get invalid document id", func(t *testing.T) {
		resp, err := store.GetAndDelete(context.Background(), "invalid id")
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "parse id")
	})

	t.Run("test expiration", func(t *testing.T) {
		storeExpired, err := New(context.Background(), client, 0)
		assert.NoError(t, err)

		claims := &oidc4ci.ClaimData{
			"claim1": "value1",
			"claim2": "value2",
		}

		id, err := storeExpired.Create(context.Background(), claims)
		assert.NoError(t, err)

		claimsInDB, err := storeExpired.GetAndDelete(context.Background(), id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, oidc4ci.ErrDataNotFound)
	})
}

func TestMigrate(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", defaultClaimsTTL)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := New(ctx, client, 3600)
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
			"27017/tcp": {{HostIP: "", HostPort: "27031"}},
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
