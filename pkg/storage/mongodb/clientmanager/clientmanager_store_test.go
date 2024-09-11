/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
)

const (
	mongoDBConnString  = "mongodb://localhost:27028"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestStore_GetClient(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	mongoClient, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, err)

	ctx := context.Background()

	clientManager, err := clientmanager.NewStore(ctx, mongoClient)
	assert.NoError(t, err)

	oauthClient := &oauth2client.Client{
		ID:     uuid.New().String(),
		Scopes: []string{"scope"},
	}

	_, err = clientManager.InsertClient(ctx, oauthClient)
	assert.NoError(t, err)

	store, err := clientmanager.NewStore(ctx, mongoClient)
	assert.NoError(t, err)

	oauthClientDB, err := store.GetClient(ctx, oauthClient.ID)
	assert.NoError(t, err)
	assert.Equal(t, oauthClient, oauthClientDB)
}

func TestStore_GetDefaultClient(t *testing.T) {
	oauthClient, err := (&clientmanager.Store{}).GetClient(context.Background(), "")
	assert.NoError(t, err)
	assert.Equal(t, fosite.DefaultClient{}, *(oauthClient.(*fosite.DefaultClient)))
}

func TestStore_ClientAssertionJWTValid(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	testCases := []struct {
		jti string
		exp time.Time
		err error
	}{
		{
			jti: "12345",
			exp: time.Now().UTC().Add(-10 * time.Hour),
			err: nil,
		},
		{
			jti: "111",
			exp: time.Now().UTC().Add(10 * time.Hour),
			err: fosite.ErrJTIKnown,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.jti, func(t *testing.T) {
			mongoClient, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
			assert.NoError(t, mongoErr)

			ctx := context.Background()

			store, err := clientmanager.NewStore(ctx, mongoClient)
			assert.NoError(t, err)

			assert.NoError(t, store.SetClientAssertionJWT(ctx, testCase.jti, testCase.exp))

			err = store.ClientAssertionJWTValid(ctx, testCase.jti)
			assert.Equal(t, testCase.err, err)
		})
	}
}

func TestInsertClient(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	s, err := clientmanager.NewStore(context.Background(), client)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	_, err = s.InsertClient(ctx, &oauth2client.Client{
		ID:     uuid.New().String(),
		Scopes: []string{"scope"},
	})

	assert.ErrorContains(t, err, "context canceled")
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27028"}},
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

	db := mongoClient.Database("test")

	return db.Client().Ping(ctx, nil)
}
