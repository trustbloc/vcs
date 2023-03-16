/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslstore

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
	mongoDBConnString  = "mongodb://localhost:27025"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
)

func TestWrapperStore(t *testing.T) {
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

	t.Run("Create, update, find wrapper VC JSON-LD", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		wrapperCreated := &credentialstatus.CSLWrapper{
			VCByte:      []byte(sampleVCJsonLD),
			UsedIndexes: []int{1},
			VC:          vc,
		}

		// Create - Find
		err = store.Upsert(ctx, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err := store.Get(ctx, vc.ID)
		assert.NoError(t, err)
		compareWrappers(t, wrapperCreated, wrapperFound)

		// Update - Find
		wrapperCreated.VC.Issuer.ID += "_123"
		vcUpdateBytes, err := wrapperCreated.VC.MarshalJSON()
		assert.NoError(t, err)
		wrapperCreated.UsedIndexes = append(wrapperCreated.UsedIndexes, 2)
		wrapperCreated.VCByte = vcUpdateBytes

		err = store.Upsert(ctx, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err = store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperCreated, wrapperFound)
	})

	t.Run("Create, update, find wrapper VC JWT", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		wrapperCreated := &credentialstatus.CSLWrapper{
			VCByte:      []byte(sampleVCJWT),
			UsedIndexes: []int{1},
			VC:          vc,
		}

		// Create - Find
		err = store.Upsert(ctx, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err := store.Get(ctx, vc.ID)
		assert.NoError(t, err)
		compareWrappers(t, wrapperCreated, wrapperFound)

		// Update - Find
		wrapperCreated.VC.Issuer.ID += "_123"
		claims, err := wrapperCreated.VC.JWTClaims(false)
		assert.NoError(t, err)

		jwt, err := claims.MarshalUnsecuredJWT()
		assert.NoError(t, err)

		wrapperCreated.UsedIndexes = append(wrapperCreated.UsedIndexes, 2)

		wrapperCreated.VCByte = []byte("\"" + jwt + "\"")

		err = store.Upsert(ctx, wrapperCreated)
		assert.NoError(t, err)

		wrapperFound, err = store.Get(ctx, vc.ID)
		assert.NoError(t, err)

		compareWrappers(t, wrapperCreated, wrapperFound)
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
		err = store.Upsert(ctxWithTimeout, &credentialstatus.CSLWrapper{
			VC: &verifiable.Credential{ID: "1"},
		})

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Get(ctxWithTimeout, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
}

func TestLatestListID(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, clientErr := mongodb.New(mongoDBConnString, "testdb2", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, clientErr)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	ctx := context.Background()

	t.Run("Find non-existing ID", func(t *testing.T) {
		listID, err := store.GetLatestListID(ctx)

		assert.NotEmpty(t, listID)
		assert.NoError(t, err)
	})

	t.Run("Update - Get LatestListID", func(t *testing.T) {
		receivedListID, err := store.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, receivedListID)

		err = store.UpdateLatestListID(ctx)
		require.NoError(t, err)

		receivedListIDAfterUpdate, err := store.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, receivedListIDAfterUpdate)
		require.NotEqual(t, receivedListID, receivedListIDAfterUpdate)
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
			"27017/tcp": {{HostIP: "", HostPort: "27025"}},
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

func compareWrappers(t *testing.T, wrapperCreated, wrapperFound *credentialstatus.CSLWrapper) {
	t.Helper()

	vcFound, err := verifiable.ParseCredential(wrapperFound.VCByte,
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	if !assert.Equal(t, wrapperCreated.VC, vcFound) {
		t.Errorf("VC got = %v, want %v",
			wrapperFound, wrapperCreated)
	}
	if !assert.Equal(t, wrapperCreated.UsedIndexes, wrapperFound.UsedIndexes) {
		t.Errorf("RevocationListIndex got = %v, want %v",
			wrapperFound, wrapperCreated)
	}
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
