/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/presexch"
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
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, e := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, e)

	store, e := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), defaultClaimsTTL)
	assert.NoError(t, e)
	assert.NotNil(t, store)
	defer func() {
		assert.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Success: create tx, update with received claims ID, delete", func(t *testing.T) {
		id, txCreate, err := store.Create(
			&presexch.PresentationDefinition{}, profileID, profileVersion, 0, []string{customScope})

		assert.NoError(t, err)
		assert.NotNil(t, id)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID:               id,
			ReceivedClaimsID: receivedClaimsID,
		}, 0)
		assert.NoError(t, err)

		txCreate.ReceivedClaimsID = receivedClaimsID

		txUpdate, err := store.Get(id)
		assert.NoError(t, err)

		assert.Equal(t, txCreate, txUpdate)

		err = store.Delete(id)
		assert.NoError(t, err)

		_, err = store.Get(id)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)

		// Delete not existing tx.
		err = store.Delete(id)
		assert.NoError(t, err)
	})
}

func TestTxStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, err)

	store, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), defaultClaimsTTL)
	assert.NoError(t, err)
	assert.NotNil(t, store)
	defer func() {
		assert.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Get invalid tx id", func(t *testing.T) {
		_, err := store.Get("invalid")
		assert.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Delete invalid tx id", func(t *testing.T) {
		err := store.Delete("invalid")
		assert.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Get empty tx id", func(t *testing.T) {
		_, err := store.Get("")
		assert.Contains(t, err.Error(), oidc4vp.ErrDataNotFound.Error())
	})

	t.Run("Get update tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "invalid",
		}, 0)
		assert.Contains(t, err.Error(), "tx invalid id")
	})

	t.Run("Get empty tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "",
		}, 0)
		assert.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Get not existing tx id", func(t *testing.T) {
		err := store.Update(oidc4vp.TransactionUpdate{
			ID: "121212121212121212121212",
		}, 0)
		assert.EqualError(t, err, "profile with given id not found")
	})

	t.Run("invalid doc content", func(t *testing.T) {
		_, err := txFromDocument(&txDocument{
			ID: primitive.ObjectID{},
			PresentationDefinition: map[string]interface{}{
				"frame": "invalid",
			},
		})

		assert.Error(t, err)
	})

	t.Run("test default expiration", func(t *testing.T) {
		storeExpired, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), 1)
		assert.NoError(t, err)

		id, _, err := storeExpired.Create(
			&presexch.PresentationDefinition{}, profileID, profileVersion, 0, []string{customScope})
		assert.NoError(t, err)
		assert.NotNil(t, id)

		time.Sleep(time.Second)

		tx, err := storeExpired.Get(id)
		assert.Nil(t, tx)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("test profile expiration", func(t *testing.T) {
		storeExpired, err := NewTxStore(context.Background(), client, testutil.DocumentLoader(t), 100)
		assert.NoError(t, err)

		id, _, err := storeExpired.Create(
			&presexch.PresentationDefinition{}, profileID, profileVersion, 1, []string{customScope})
		assert.NoError(t, err)
		assert.NotNil(t, id)

		time.Sleep(time.Second)

		tx, err := storeExpired.Get(id)
		assert.Nil(t, tx)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})
}

func TestMigrate(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(defaultClaimsTTL))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := NewTxStore(ctx, client, testutil.DocumentLoader(t), defaultClaimsTTL)
	assert.Nil(t, store)
	assert.ErrorContains(t, err, "context canceled")

	defer func() {
		assert.NoError(t, client.Close(), "failed to close mongodb client")
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

	clientOpts := options.Client().ApplyURI(mongoDBConnString)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return err
	}

	db := mongoClient.Database("test")

	return db.Client().Ping(ctx, nil)
}
