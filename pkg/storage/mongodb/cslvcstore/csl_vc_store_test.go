/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslvcstore

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
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27033"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
)

func TestCSLStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10000))
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	ctx := context.Background()

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create, update, find VC JSON-LD", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		wrapperCreated := &credentialstatus.CSLVCWrapper{
			VCByte:  []byte(sampleVCJsonLD),
			Version: 1,
		}

		// Create - Find
		err = store.Upsert(ctx, vc.ID, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err := store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperCreated, wrapperFound)

		// Update - Find
		vc.Issuer.ID += "_123"
		vcUpdateBytes, err := vc.MarshalJSON()
		assert.NoError(t, err)

		wrapperUpdated := &credentialstatus.CSLVCWrapper{
			VCByte:  vcUpdateBytes,
			Version: 2,
		}

		err = store.Upsert(ctx, vc.ID, wrapperUpdated)
		assert.NoError(t, err)

		wrapperFound, err = store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperUpdated, wrapperFound)
	})

	t.Run("Create, update, find wrapper VC JWT", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		wrapperCreated := &credentialstatus.CSLVCWrapper{
			VCByte:  []byte(sampleVCJWT),
			Version: 1,
		}

		// Create - Find
		err = store.Upsert(ctx, vc.ID, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err := store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperCreated, wrapperFound)

		// Update - Find
		vc.Issuer.ID += "_123"
		claims, err := vc.JWTClaims(false)
		assert.NoError(t, err)

		jwt, err := claims.MarshalUnsecuredJWT()
		assert.NoError(t, err)

		vcBytes := []byte("\"" + jwt + "\"")

		wrapperUpdated := &credentialstatus.CSLVCWrapper{
			VCByte:  vcBytes,
			Version: 2,
		}

		err = store.Upsert(ctx, vc.ID, wrapperUpdated)
		assert.NoError(t, err)

		wrapperFound, err = store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperUpdated, wrapperFound)
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		resp, err := store.Get(ctx, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorIs(t, err, credentialstatus.ErrDataNotFound)
	})
}

func TestTimeouts(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", mongodb.WithTimeout(5))
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	ctxWithTimeout, cancel := client.ContextWithTimeout()
	defer cancel()

	t.Run("Create timeout", func(t *testing.T) {
		err = store.Upsert(ctxWithTimeout, "1", nil)

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Get(ctxWithTimeout, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
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
			"27017/tcp": {{HostIP: "", HostPort: "27033"}},
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

func TestStore_GetCSLURL(t *testing.T) {
	store := NewStore(nil)
	require.NotNil(t, store)

	cslURL, err := store.GetCSLURL(
		"https://example.com", "test_issuer", "1-abcd")
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/issuer/groups/test_issuer/credentials/status/1-abcd", cslURL)

	cslURL, err = store.GetCSLURL(
		" https://example.com", "test_issuer", "1")
	assert.Error(t, err)
	assert.Empty(t, cslURL)
}

func compareWrappers(t *testing.T, wrapperExpected, wrapperFound *credentialstatus.CSLVCWrapper) {
	t.Helper()

	vcExpected, err := verifiable.ParseCredential(wrapperExpected.VCByte,
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	vcFound, err := verifiable.ParseCredential(wrapperFound.VCByte,
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	if !assert.Equal(t, vcExpected, vcFound) {
		t.Errorf("VC got = %v, want %v",
			wrapperFound, wrapperExpected)
	}

	if !assert.Equal(t, wrapperExpected.Version, wrapperFound.Version) {
		t.Errorf("Version: got = %v, want %v",
			wrapperFound, wrapperExpected)
	}
}
