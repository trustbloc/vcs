/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb_test

import (
	"context"
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
	"go.mongodb.org/mongo-driver/mongo/readpref"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27039"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
	testDatabaseName   = "test_db"
	testTimeout        = 5 * time.Second
)

func TestClient(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, testDatabaseName,
		mongodb.WithTimeout(testTimeout),
		mongodb.WithReadPref(readpref.PrimaryPreferred()),
		mongodb.WithTraceProvider(nooptracer.NewTracerProvider()),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	require.Equal(t, testDatabaseName, client.Database().Name())
	require.NoError(t, client.Close())
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27039"}},
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return err
	}

	db := mongoClient.Database(testDatabaseName)

	return db.Client().Ping(ctx, nil)
}
