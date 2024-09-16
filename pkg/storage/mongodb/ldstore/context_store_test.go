/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/trustbloc/kms-go/spi/storage"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	"github.com/trustbloc/did-go/doc/ld/context/embed"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/ldstore"
)

const (
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

const (
	sampleJSONLDContext = `
{
  "@context": {
    "name": "http://xmlns.com/foaf/0.1/name",
    "homepage": {
      "@id": "http://xmlns.com/foaf/0.1/homepage",
      "@type": "@id"
    }
  }
}`
	sampleContextURL      = "https://example.com/context.jsonld"
	contextCollectionName = "ldcontext"
)

func TestContextStore(t *testing.T) {
	connectionString := "mongodb://localhost:27019"

	pool, mongoDBResource := startMongoDBContainer(t, connectionString, "27019")

	t.Cleanup(func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	})

	client, clientErr := mongodb.New(connectionString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, clientErr)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	collection := client.Database().Collection(contextCollectionName)

	t.Run("test store, retrieve and delete", func(t *testing.T) {
		store, err := ldstore.NewContextStore(client)
		require.NoError(t, err)

		doc, err := jsonld.DocumentFromReader(bytes.NewReader(json.RawMessage(sampleJSONLDContext)))
		require.NoError(t, err)

		rd := &jsonld.RemoteDocument{
			Document:   doc,
			ContextURL: sampleContextURL,
		}

		err = store.Put(sampleContextURL, rd)
		require.NoError(t, err)

		got, err := store.Get(sampleContextURL)
		require.NoError(t, err)
		require.Equal(t, rd, got)

		err = store.Delete([]ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		})
		require.NoError(t, err)

		_, err = store.Get(sampleContextURL)
		require.ErrorIs(t, err, storage.ErrDataNotFound)
	})

	t.Run("test import", func(t *testing.T) {
		store, err := ldstore.NewContextStore(client)
		require.NoError(t, err)

		err = store.Import(embed.Contexts)
		require.NoError(t, err)

		ctxWithTimeout, cancel := client.ContextWithTimeout()
		t.Cleanup(cancel)

		count, err := collection.CountDocuments(ctxWithTimeout, bson.D{})
		require.NoError(t, err)
		require.Equal(t, len(embed.Contexts), int(count))

		// contexts in db are up-to-date
		err = store.Import(embed.Contexts)
		require.NoError(t, err)

		count, err = collection.CountDocuments(ctxWithTimeout, bson.D{})
		require.NoError(t, err)
		require.Equal(t, len(embed.Contexts), int(count))

		// remove one context and import again
		err = store.Delete([]ldcontext.Document{embed.Contexts[0]})
		require.NoError(t, err)

		count, err = collection.CountDocuments(ctxWithTimeout, bson.D{})
		require.NoError(t, err)
		require.Equal(t, len(embed.Contexts)-1, int(count))

		err = store.Import(embed.Contexts)
		require.NoError(t, err)

		count, err = collection.CountDocuments(ctxWithTimeout, bson.D{})
		require.NoError(t, err)
		require.Equal(t, len(embed.Contexts), int(count))
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
