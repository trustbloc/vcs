/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpclaimsstore

import (
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
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
	mongoDBConnString  = "mongodb://localhost:27031"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
	defaultClaimsTTL   = 3600
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
	//go:embed testdata/university_degree.sdjwt
	sampleVCSDJWT string
)

func TestStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, createErr := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, createErr)

	store, createErr := New(context.Background(), client, testutil.DocumentLoader(t), defaultClaimsTTL)
	assert.NoError(t, createErr)

	t.Run("test create and get - JWT", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		receivedClaims := &oidc4vp.ReceivedClaims{
			Credentials: map[string]*verifiable.Credential{"credID": vc},
		}

		id, err := store.Create(receivedClaims)
		require.NoError(t, err)

		claimsInDB, err := store.Get(id)
		assert.NoError(t, err)
		require.NotNil(t, claimsInDB)

		require.NotNil(t, claimsInDB.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", claimsInDB.Credentials["credID"].ID)
		assert.Equal(t, receivedClaims, claimsInDB)
	})

	t.Run("test create and get - SD-JWT", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCSDJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		receivedClaims := &oidc4vp.ReceivedClaims{
			Credentials: map[string]*verifiable.Credential{"credID": vc},
		}

		id, err := store.Create(receivedClaims)
		require.NoError(t, err)

		claimsInDB, err := store.Get(id)
		assert.NoError(t, err)
		assert.NotNil(t, claimsInDB)

		require.NotNil(t, claimsInDB.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", claimsInDB.Credentials["credID"].ID)
		assert.Equal(t, receivedClaims, claimsInDB)
	})

	t.Run("test create and get - JSON LD", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		receivedClaims := &oidc4vp.ReceivedClaims{
			Credentials: map[string]*verifiable.Credential{"credID": vc},
		}

		id, err := store.Create(receivedClaims)
		require.NoError(t, err)

		claimsInDB, err := store.Get(id)
		assert.NoError(t, err)
		require.NotNil(t, claimsInDB)

		require.NotNil(t, claimsInDB.Credentials["credID"])
		require.Equal(t, "http://example.gov/credentials/3732", claimsInDB.Credentials["credID"].ID)
		assert.Equal(t, receivedClaims, claimsInDB)
	})

	t.Run("get non existing document", func(t *testing.T) {
		id := primitive.NewObjectID().Hex()

		resp, err := store.Get(id)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})

	t.Run("get invalid document id", func(t *testing.T) {
		resp, err := store.Get("invalid id")
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "parse id")
	})

	t.Run("invalid doc content", func(t *testing.T) {
		_, err := receivedClaimsFromDocument(&mongoDocument{
			ID: primitive.ObjectID{},
			ReceivedClaims: map[string][]byte{
				"credentials": []byte("invalid"),
			},
		}, testutil.DocumentLoader(t))

		require.Error(t, err)
	})

	t.Run("test expiration", func(t *testing.T) {
		storeExpired, err := New(context.Background(), client, testutil.DocumentLoader(t), 0)
		assert.NoError(t, err)

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		receivedClaims := &oidc4vp.ReceivedClaims{
			Credentials: map[string]*verifiable.Credential{"credID": jwtvc},
		}

		id, err := storeExpired.Create(receivedClaims)
		require.NoError(t, err)

		claimsInDB, err := storeExpired.Get(id)
		assert.Nil(t, claimsInDB)
		assert.ErrorIs(t, err, oidc4vp.ErrDataNotFound)
	})
}

func TestMigrate(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", defaultClaimsTTL)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := New(ctx, client, testutil.DocumentLoader(t), 3600)
	assert.Nil(t, store)
	assert.ErrorContains(t, err, "context canceled")

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
			"27017/tcp": {{HostIP: "", HostPort: "27031"}},
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
