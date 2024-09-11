/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcissuancehistorystore

import (
	"context"
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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	mongoDBConnString    = "mongodb://localhost:27028"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTag     = "4.0.0"
	testProfile          = "test_profile"
	testProfileVersion10 = "v1.0"
)

func TestVCIssuanceHistoryStore(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, errDocker := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, errDocker)

	store := NewStore(client)
	require.NotNil(t, store)

	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	ctx := context.Background()

	t.Run("Put and GetIssuedCredentialsMetadata", func(t *testing.T) {
		transactionID := uuid.NewString()
		credentialMeta := &credentialstatus.CredentialMetadata{
			CredentialID:   "credentialID",
			ProfileVersion: testProfileVersion10,
			Issuer:         "credentialIssuerID",
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  transactionID,
			IssuanceDate:   timeutil.NewTime(time.Now().Round(time.Second).UTC()),
			ExpirationDate: nil,
		}

		// Create.
		err := store.Put(ctx, testProfile, testProfileVersion10, credentialMeta)
		assert.NoError(t, err)

		// Get credential metadata by same profile version.
		metadataFromDB, err := store.GetIssuedCredentialsMetadata(ctx, testProfile, nil, nil)
		assert.NoError(t, err)

		assert.Equal(t, []*credentialstatus.CredentialMetadata{credentialMeta}, metadataFromDB)

		// Create another record.
		credentialMetaNew := &credentialstatus.CredentialMetadata{}
		*credentialMetaNew = *credentialMeta
		credentialMetaNew.CredentialID = "credentialIDNew"
		credentialMetaNew.IssuanceDate = timeutil.NewTime(time.Now().Add(time.Hour).Round(time.Second).UTC())
		err = store.Put(ctx, testProfile, testProfileVersion10, credentialMetaNew)
		assert.NoError(t, err)

		// Get credential metadata by same profile version.
		metadataFromDB, err = store.GetIssuedCredentialsMetadata(ctx, testProfile, nil, nil)
		assert.NoError(t, err)

		assert.Equal(t, []*credentialstatus.CredentialMetadata{credentialMetaNew, credentialMeta}, metadataFromDB)
	})

	t.Run("Find non-existing document", func(t *testing.T) {
		// Get credential metadata by different profile version.
		metadataFromDB, err := store.GetIssuedCredentialsMetadata(ctx, testProfile+"unknown", nil, nil)
		assert.NoError(t, err)
		assert.Empty(t, metadataFromDB)
	})

	t.Run("Test transaction id filter", func(t *testing.T) {
		transactionID := uuid.NewString()
		credentialMeta := &credentialstatus.CredentialMetadata{
			CredentialID:   "credentialID",
			ProfileVersion: testProfileVersion10,
			Issuer:         "credentialIssuerID",
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  transactionID,
			IssuanceDate:   timeutil.NewTime(time.Now().Round(time.Second).UTC()),
			ExpirationDate: nil,
		}
		assert.NoError(t, store.Put(ctx, testProfile, testProfileVersion10, credentialMeta))

		transactionID2 := uuid.NewString()
		credentialMeta2 := &credentialstatus.CredentialMetadata{
			CredentialID:   "credentialID",
			ProfileVersion: testProfileVersion10,
			Issuer:         "credentialIssuerID",
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  transactionID2,
			IssuanceDate:   timeutil.NewTime(time.Now().Round(time.Second).UTC()),
			ExpirationDate: nil,
		}
		assert.NoError(t, store.Put(ctx, testProfile, testProfileVersion10, credentialMeta2))

		resp, err := store.GetIssuedCredentialsMetadata(ctx, testProfile, &transactionID2, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		assert.EqualValues(t, credentialMeta2.TransactionID, resp[0].TransactionID)
	})

	t.Run("Test credential id filter", func(t *testing.T) {
		transactionID := uuid.NewString()
		credentialMeta := &credentialstatus.CredentialMetadata{
			CredentialID:   "credentialID123",
			ProfileVersion: testProfileVersion10,
			Issuer:         "credentialIssuerID",
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  transactionID,
			IssuanceDate:   timeutil.NewTime(time.Now().Round(time.Second).UTC()),
			ExpirationDate: nil,
		}
		assert.NoError(t, store.Put(ctx, testProfile, testProfileVersion10, credentialMeta))

		transactionID2 := uuid.NewString()
		credentialMeta2 := &credentialstatus.CredentialMetadata{
			CredentialID:   "777",
			ProfileVersion: testProfileVersion10,
			Issuer:         "credentialIssuerID",
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  transactionID2,
			IssuanceDate:   timeutil.NewTime(time.Now().Round(time.Second).UTC()),
			ExpirationDate: nil,
		}
		assert.NoError(t, store.Put(ctx, testProfile, testProfileVersion10, credentialMeta2))

		resp, err := store.GetIssuedCredentialsMetadata(ctx, testProfile, nil, &credentialMeta2.CredentialID)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		assert.EqualValues(t, credentialMeta2.CredentialID, resp[0].CredentialID)
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
		err = store.Put(ctxWithTimeout, testProfile, testProfileVersion10, &credentialstatus.CredentialMetadata{})

		assert.ErrorContains(t, err, "context deadline exceeded")
	})

	t.Run("Find GetIssuedCredentialsMetadata", func(t *testing.T) {
		resp, err := store.GetIssuedCredentialsMetadata(ctxWithTimeout, testProfile, nil, nil)

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
