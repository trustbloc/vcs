/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	mongocheck "github.com/trustbloc/vcs/component/healthchecks/mongo"
)

const (
	mongoDBConnString  = "mongodb://localhost:27041"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestSuccess(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	})

	err := mongocheck.New(mongoDBConnString)(context.Background())

	require.NoError(t, err)
}

func TestFailToPingMongoDB(t *testing.T) {
	errCh := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		errCh <- mongocheck.New(mongoDBConnString)(ctx)
	}()

	cancel()

	require.ErrorContains(t, <-errCh, "failed to ping mongodb")
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27041"}},
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
