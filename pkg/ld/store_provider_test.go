/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/golang/mock/gomock"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
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

	client, clientErr := mongodb.New(connectionString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, clientErr)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	t.Run("Success", func(t *testing.T) {
		provider, err := ld.NewStoreProvider(client, NewMockCache(gomock.NewController(t)))

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

	clientOpts := options.Client().ApplyURI(connectionString)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return err
	}

	db := mongoClient.Database("test")

	return db.Client().Ping(ctx, nil)
}
