/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

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
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
	"github.com/trustbloc/vc-go/verifiable"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString    = "mongodb://localhost:27026"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTag     = "4.0.0"
	testProfile          = "test_profile"
	testProfileVersion10 = "v1.0"
	testProfileVersion11 = "v1.1"
	testVCID             = "test_vc_id"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/multi_status.jsonld
	multiStatusVCJsonLD string
)

func TestVCStatusStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	vcExpected, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	vccExpected := vcExpected.Contents()

	require.Len(t, vccExpected.Status, 1)

	ctx := context.Background()

	// Create.
	err = store.Put(ctx, testProfile, testProfileVersion10, vccExpected.ID, vccExpected.Status[0])
	require.NoError(t, err)

	t.Run("Get typedID", func(t *testing.T) {
		// Find verifiable.TypedID by same profile version.
		statusFound, err := store.Get(ctx, testProfile, testProfileVersion10, vccExpected.ID, "")
		require.NoError(t, err)

		if !assert.Equal(t, vccExpected.Status[0], statusFound) {
			t.Errorf("VC Status got = %v, want %v",
				vccExpected.Status, statusFound)
		}

		// Find verifiable.TypedID by different profile version.
		statusFound, err = store.Get(ctx, testProfile, testProfileVersion11, vccExpected.ID, statustype.StatusPurposeRevocation)
		assert.Error(t, err)
		assert.Empty(t, statusFound)
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		resp, err := store.Get(
			context.Background(), testProfile, testProfileVersion10, "63451f2358bde34a13b5d95b", statustype.StatusPurposeRevocation)

		assert.Nil(t, resp)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestVCStatusStoreMultiStatus(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, err)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	vcExpected, err := verifiable.ParseCredential([]byte(multiStatusVCJsonLD),
		verifiable.WithJSONLDDocumentLoader(loader),
		verifiable.WithDisabledProofCheck())
	require.NoError(t, err)

	vccExpected := vcExpected.Contents()

	require.Len(t, vccExpected.Status, 2)

	require.NoError(t, store.Put(context.Background(), testProfile, testProfileVersion10, vccExpected.ID, vccExpected.Status[0]))
	require.NoError(t, store.Put(context.Background(), testProfile, testProfileVersion10, vccExpected.ID, vccExpected.Status[1]))

	t.Run("Get typedID - multi-status", func(t *testing.T) {
		statusFound, err := store.Get(context.Background(), testProfile, testProfileVersion10, vccExpected.ID, statustype.StatusPurposeRevocation)
		require.NoError(t, err)
		require.Equalf(t, vccExpected.Status[0], statusFound, "VC Status got = %v, want %v")

		statusFound, err = store.Get(context.Background(), testProfile, testProfileVersion10, vccExpected.ID, statustype.StatusPurposeSuspension)
		require.NoError(t, err)
		require.Equalf(t, vccExpected.Status[1], statusFound, "VC Status got = %v, want %v")
	})

	t.Run("Find with unsupported status", func(t *testing.T) {
		resp, err := store.Get(
			context.Background(), testProfile, testProfileVersion10, vccExpected.ID, "unsupported")
		require.ErrorIs(t, err, ErrNotFound)
		require.Nil(t, resp)
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
		err = store.Put(ctxWithTimeout, testProfile, testProfileVersion10, testVCID, &verifiable.TypedID{ID: "1"})

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Get(ctxWithTimeout, testProfile, testProfileVersion10, "63451f2358bde34a13b5d95b", statustype.StatusPurposeRevocation)

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
