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
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
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
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
	//go:embed testdata/university_degree.sdjwt
	sampleVCSDJWT string
)

func TestTxStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := NewTxStore(client, testutil.DocumentLoader(t))
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create tx", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create tx then Get by id", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")

		require.NoError(t, err)
		require.NotNil(t, id)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
	})

	t.Run("Create tx then update with jwt vc", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")

		require.NoError(t, err)
		require.NotNil(t, id)

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID: id,
			ReceivedClaims: &oidc4vp.ReceivedClaims{
				Credentials: map[string]*verifiable.Credential{"credID": jwtvc},
			},
		})
		require.NoError(t, err)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.NotNil(t, tx.ReceivedClaims.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", tx.ReceivedClaims.Credentials["credID"].ID)
	})

	t.Run("Create tx then update with sdjwt vc", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")

		require.NoError(t, err)
		require.NotNil(t, id)

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCSDJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID: id,
			ReceivedClaims: &oidc4vp.ReceivedClaims{
				Credentials: map[string]*verifiable.Credential{"credID": jwtvc},
			},
		})
		require.NoError(t, err)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.NotNil(t, tx.ReceivedClaims.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", tx.ReceivedClaims.Credentials["credID"].ID)
	})

	t.Run("Create tx then update with ld vc", func(t *testing.T) {
		id, err := store.Create(&presexch.PresentationDefinition{}, "test")

		require.NoError(t, err)
		require.NotNil(t, id)

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = store.Update(oidc4vp.TransactionUpdate{
			ID: id,
			ReceivedClaims: &oidc4vp.ReceivedClaims{
				Credentials: map[string]*verifiable.Credential{"credID": jwtvc},
			},
		})
		require.NoError(t, err)

		tx, err := store.Get(id)
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.NotNil(t, tx.ReceivedClaims.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", tx.ReceivedClaims.Credentials["credID"].ID)
	})
}

func TestTxStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := NewTxStore(client, testutil.DocumentLoader(t))
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
		}, testutil.DocumentLoader(t))

		require.Error(t, err)
	})

	t.Run("invalid doc content", func(t *testing.T) {
		_, err := txFromDocument(&txDocument{
			ID: primitive.ObjectID{},
			ReceivedClaims: map[string][]byte{
				"credentials": []byte("invalid"),
			},
		}, testutil.DocumentLoader(t))

		require.Error(t, err)
	})
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
