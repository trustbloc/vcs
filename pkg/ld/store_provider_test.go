/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestNewStoreProvider(t *testing.T) {
	connectionString := "mongodb://localhost:27029"

	pool, mongoDBResource := startMongoDBContainer(t, connectionString, "27029")

	t.Cleanup(func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	})

	client, clientErr := mongodb.New(connectionString, "testdb", time.Second*10, nil)
	require.NoError(t, clientErr)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	t.Run("Success", func(t *testing.T) {
		provider, err := ld.NewStoreProvider(client)

		require.NotNil(t, provider)
		require.NoError(t, err)
		require.NotNil(t, provider.JSONLDContextStore())
		require.NotNil(t, provider.JSONLDRemoteProviderStore())
	})
}

func startMongoDBContainer(t *testing.T, connectionString, port string) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: port}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp(connectionString))

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp(connectionString string) error {
	return backoff.Retry(func() error {
		return pingMongoDB(connectionString)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB(connectionString string) error {
	var err error

	tM := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistryBuilder().RegisterTypeMapEntry(bsontype.EmbeddedDocument, tM).Build()
	clientOpts := options.Client().SetRegistry(reg).ApplyURI(connectionString)

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
