/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstore

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
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString  = "mongodb://localhost:27026"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
	testProfile        = "test_profile"
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

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10, nil)
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Put, Get VC JSON-LD", func(t *testing.T) {
		vcExpected, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		// Create - Find
		err = store.Put(testProfile, vcExpected)
		assert.NoError(t, err)

		vcFoundBytes, err := store.Get(testProfile, vcExpected.ID)
		assert.NoError(t, err)

		vcFound, err := verifiable.ParseCredential(vcFoundBytes,
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		if !assert.Equal(t, vcExpected, vcFound) {
			t.Errorf("VC got = %v, want %v",
				vcExpected, vcFound)
		}
	})

	t.Run("Put, Get VC JWT", func(t *testing.T) {
		vcExpected, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)
		vcExpected.JWT = sampleVCJWT

		// Create - Find
		err = store.Put(testProfile, vcExpected)
		assert.NoError(t, err)

		vcFoundBytes, err := store.Get(testProfile, vcExpected.ID)
		assert.NoError(t, err)

		vcFound, err := verifiable.ParseCredential(vcFoundBytes,
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)
		vcFound.JWT = sampleVCJWT

		if !assert.Equal(t, vcExpected, vcFound) {
			t.Errorf("VC got = %v, want %v",
				vcExpected, vcFound)
		}
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		resp, err := store.Get(testProfile, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "failed to query MongoDB")
	})
}

func TestTimeouts(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb2", 5, nil)
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create timeout", func(t *testing.T) {
		err = store.Put(testProfile, &verifiable.Credential{ID: "1"})

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Get(testProfile, "63451f2358bde34a13b5d95b")

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
			"27017/tcp": {{HostIP: "", HostPort: "27026"}},
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
