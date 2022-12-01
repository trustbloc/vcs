/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requestobjectstore

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27022"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27022"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func TestObjectStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create Object", func(t *testing.T) {
		resp, err := store.Create(requestobject.RequestObject{
			Content: "random-content",
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("Create and find by id", func(t *testing.T) {
		u := uuid.New()

		eventData := json.RawMessage(`{"test":"test"}`)

		expectedEvent := spi.Event{
			SpecVersion:     "test1",
			ID:              "test2",
			Source:          "test2",
			Type:            "test4",
			DataContentType: "test5",
			Time:            nil,
			Data:            eventData,
		}

		resp, err := store.Create(requestobject.RequestObject{
			Content:                  u,
			AccessRequestObjectEvent: &expectedEvent,
		})

		assert.NoError(t, err)

		resp2, err2 := store.Find(resp.ID)

		assert.NoError(t, err2)
		assert.Equal(t, u, resp2.Content)

		if !reflect.DeepEqual(resp2.AccessRequestObjectEvent.Data, expectedEvent.Data) {
			t.Errorf("ValidateCredential() got = %v, want %v",
				resp2.AccessRequestObjectEvent, expectedEvent)
		}
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		resp2, err2 := store.Find("63451f2358bde34a13b5d95b")

		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, requestobject.ErrDataNotFound)
	})

	t.Run("Create Invalid key mapping", func(t *testing.T) {
		resp2, err2 := store.Find("123")

		assert.Nil(t, resp2)
		assert.ErrorContains(t, err2, "the provided hex string is not a valid ObjectID")
	})

	t.Run("Delete existing document", func(t *testing.T) {
		u := uuid.New()

		resp, err := store.Create(requestobject.RequestObject{
			Content: u,
		})

		assert.NoError(t, err)

		err2 := store.Delete(resp.ID)
		assert.NoError(t, err2)

		resp2, err2 := store.Find(resp.ID)

		assert.Nil(t, resp2)
		assert.ErrorIs(t, err2, requestobject.ErrDataNotFound)
	})

	t.Run("Delete non-existing document", func(t *testing.T) {
		err2 := store.Delete("63451f2358bde34a13b5d95b")

		assert.NoError(t, err2)
	})

	t.Run("Delete Invalid key mapping", func(t *testing.T) {
		err2 := store.Delete("123")

		assert.ErrorContains(t, err2, "the provided hex string is not a valid ObjectID")
	})
}

func TestTimeouts(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", 5)
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create timeout", func(t *testing.T) {
		resp, err := store.Create(requestobject.RequestObject{
			Content: "random-content",
		})

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Find("63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
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
