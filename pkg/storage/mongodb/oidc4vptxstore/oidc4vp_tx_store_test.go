/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/presexch"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27021"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"

	receivedClaimsID = "xyz"
	defaultClaimsTTL = 3600

	profileID      = "testProfileID"
	profileVersion = "v1.0"
	customScope    = "customScope"
)

func TestTxStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, err)

	store, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), defaultClaimsTTL)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create tx", func(t *testing.T) {
		id, _, err := store.Create(&presexch.PresentationDefinition{}, profileID, profileVersion, customScope)
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create tx then Get by id", func(t *testing.T) {
		id, _, err := store.Create(&presexch.PresentationDefinition{}, profileID, profileVersion, customScope)

		require.NoError(t, err)
		require.NotNil(t, id)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, customScope, tx.CustomScope)
	})

	t.Run("Create tx then update with received claims ID", func(t *testing.T) {
		id, _, err := store.Create(&presexch.PresentationDefinition{}, profileID, profileVersion, "")

		require.NoError(t, err)
		require.NotNil(t, id)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID:               id,
			ReceivedClaimsID: receivedClaimsID,
		})
		require.NoError(t, err)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Nil(t, tx.ReceivedClaims)
		require.Empty(t, tx.CustomScope)
	})
}

func TestTxStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, err)

	store, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), defaultClaimsTTL)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Get invalid tx id", func(t *testing.T) {
		_, err := store.Get("invalid")
		require.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Get empty tx id", func(t *testing.T) {
		_, err := store.Get("")
		require.Contains(t, err.Error(), oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("Get not existing tx id", func(t *testing.T) {
		_, err := store.Get("121212121212121212121212")
		require.EqualError(t, err, oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("Get update tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "invalid",
		})
		require.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Get empty tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "",
		})
		require.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Get not existing tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "121212121212121212121212",
		})
		require.EqualError(t, err, "profile with given id not found")
	})

	t.Run("invalid doc content", func(t *testing.T) {
		_, err := txFromDocument(&txDocument{
			ID: primitive.ObjectID{},
			PresentationDefinition: map[string]interface{}{
				"frame": "invalid",
			},
		})

		require.Error(t, err)
	})

	t.Run("test expiration", func(t *testing.T) {
		storeExpired, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), 1)
		require.NoError(t, err)

		id, _, err := storeExpired.Create(&presexch.PresentationDefinition{}, profileID, profileVersion, customScope)
		require.NoError(t, err)
		require.NotNil(t, id)

		time.Sleep(2 * time.Second)

		tx, err := storeExpired.Get(id)
		require.Nil(t, tx)
		require.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})
}

func TestMigrate(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(defaultClaimsTTL))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := NewTxStore(ctx, client, testutil.DocumentLoader(t), defaultClaimsTTL)
	require.Nil(t, store)
	require.ErrorContains(t, err, "context canceled")

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
