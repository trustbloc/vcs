/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timeutil "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
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

	ctx := context.Background()
	transactionID := uuid.NewString()
	credentialMeta := &credentialstatus.CredentialMetadata{
		CredentialID:   vccExpected.ID,
		Issuer:         vccExpected.Issuer.ID,
		CredentialType: vccExpected.Types,
		TransactionID:  transactionID,
		IssuanceDate:   timeutil.NewTime(vccExpected.Issued.Time),
		ExpirationDate: vccExpected.Expired,
	}

	// Create.
	err = store.Put(ctx, testProfile, testProfileVersion10, credentialMeta, vccExpected.Status)
	assert.NoError(t, err)

	t.Run("Get typedID", func(t *testing.T) {
		// Find verifiable.TypedID by same profile version.
		statusFound, err := store.Get(ctx, testProfile, testProfileVersion10, vccExpected.ID)
		assert.NoError(t, err)

		if !assert.Equal(t, vccExpected.Status, statusFound) {
			t.Errorf("VC Status got = %v, want %v",
				vccExpected.Status, statusFound)
		}

		// Find verifiable.TypedID by different profile version.
		statusFound, err = store.Get(ctx, testProfile, testProfileVersion11, vccExpected.ID)
		assert.Error(t, err)
		assert.Empty(t, statusFound)
	})

	t.Run("GetIssuedCredentialsMetadata", func(t *testing.T) {
		// Get credential metadata by same profile version.
		metadataFromDB, err := store.GetIssuedCredentialsMetadata(ctx, testProfile, testProfileVersion10)
		assert.NoError(t, err)

		assert.Equal(t, []*credentialstatus.CredentialMetadata{credentialMeta}, metadataFromDB)

		// Create another record.
		err = store.Put(ctx, testProfile, testProfileVersion10, credentialMeta, vccExpected.Status)
		assert.NoError(t, err)

		// Get credential metadata by same profile version.
		metadataFromDB, err = store.GetIssuedCredentialsMetadata(ctx, testProfile, testProfileVersion10)
		assert.NoError(t, err)

		assert.Equal(t, []*credentialstatus.CredentialMetadata{credentialMeta, credentialMeta}, metadataFromDB)

		// Get credential metadata by different profile version.
		metadataFromDB, err = store.GetIssuedCredentialsMetadata(ctx, testProfile+"unknown", testProfileVersion10)
		assert.NoError(t, err)
		assert.Empty(t, metadataFromDB)
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		resp, err := store.Get(
			context.Background(), testProfile, testProfileVersion10, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "find and decode MongoDB")
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
		meta := &credentialstatus.CredentialMetadata{}
		err = store.Put(ctxWithTimeout, testProfile, testProfileVersion10, meta, &verifiable.TypedID{ID: "1"})

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find Timeout", func(t *testing.T) {
		resp, err := store.Get(ctxWithTimeout, testProfile, testProfileVersion10, "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find GetIssuedCredentialsMetadata", func(t *testing.T) {
		resp, err := store.GetIssuedCredentialsMetadata(ctxWithTimeout, testProfile, testProfileVersion10)

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
