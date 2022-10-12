/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	mongodbvcsprovider "github.com/trustbloc/vcs/pkg/storage/mongodbprovider"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesspi "github.com/hyperledger/aries-framework-go/spi/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

const (
	mongoDBConnString  = "mongodb://localhost:27017"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestSuccessCases(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	provider, err := mongodb.NewProvider(mongoDBConnString)
	require.NoError(t, err)

	storageProvider := mongodbvcsprovider.New(provider)

	t.Run("Get Aries storage provider", func(t *testing.T) {
		returnedAriesProvider := storageProvider.GetAriesProvider()
		require.Equal(t, provider, returnedAriesProvider)
	})
	t.Run("Using master key store", func(t *testing.T) {
		masterKeyStore, err := storageProvider.OpenMasterKeyStore()
		require.NoError(t, err)

		testBytes := []byte{0, 1, 1, 2, 3, 5, 8, 13, 21, 34}

		err = masterKeyStore.Put(testBytes)
		require.NoError(t, err)

		retrievedBytes, err := masterKeyStore.Get()
		require.NoError(t, err)
		require.Equal(t, testBytes, retrievedBytes)
	})
	t.Run("Using VC LDP store", func(t *testing.T) {
		vcStore, err := storageProvider.OpenVCStore()
		require.NoError(t, err)

		const testVCID = "TestVCID"

		vc := &verifiable.Credential{ID: testVCID}

		const testProfileName = "TestProfileName"

		err = vcStore.Put(testProfileName, vc)
		require.NoError(t, err)

		vcBytes, err := vcStore.Get(testProfileName, testVCID)
		require.NoError(t, err)

		// Unmarshal into a map instead of using verifiable.ParseCredential since that
		// requires a lot of extra steps and dependencies.
		var vcAsMap map[string]interface{}

		err = json.Unmarshal(vcBytes, &vcAsMap)
		require.NoError(t, err)

		require.Equal(t, testVCID, vcAsMap["id"])
	})
	t.Run("Using VC JWT store", func(t *testing.T) {
		vcStore, err := storageProvider.OpenVCStore()
		require.NoError(t, err)

		const testVCID = "TestVCID"

		vc := &verifiable.Credential{ID: testVCID, JWT: "abc"}

		const testProfileName = "TestProfileName"

		err = vcStore.Put(testProfileName, vc)
		require.NoError(t, err)

		vcBytes, err := vcStore.Get(testProfileName, testVCID)
		require.NoError(t, err)

		// Unmarshal into a map instead of using verifiable.ParseCredential since that
		// requires a lot of extra steps and dependencies.
		var vcAsMap map[string]interface{}

		err = json.Unmarshal(vcBytes, &vcAsMap)
		require.NoError(t, err)

		require.Equal(t, testVCID, vcAsMap["id"])
		require.Equal(t, "abc", vcAsMap["jwt"])
	})
	t.Run("Using CSL store", func(t *testing.T) {
		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		const testVCID = "TestVCID"

		vc := &verifiable.Credential{ID: testVCID}

		vcBytes, err := json.Marshal(vc)
		require.NoError(t, err)

		testCSLWrapper := vcsstorage.CSLWrapper{VCByte: vcBytes, ListID: 1, VC: vc}

		err = cslStore.PutCSLWrapper(&testCSLWrapper)
		require.NoError(t, err)

		retrievedCSLWrapper, err := cslStore.GetCSLWrapper(vc.ID)
		require.NoError(t, err)

		require.Equal(t, string(vcBytes), string(retrievedCSLWrapper.VCByte))

		latestListID := 1

		err = cslStore.UpdateLatestListID(latestListID)
		require.NoError(t, err)

		retrievedLatestListID, err := cslStore.GetLatestListID()
		require.NoError(t, err)
		require.Equal(t, latestListID, retrievedLatestListID)

		latestListID++

		err = cslStore.UpdateLatestListID(latestListID)
		require.NoError(t, err)

		retrievedLatestListID, err = cslStore.GetLatestListID()
		require.NoError(t, err)
		require.Equal(t, latestListID, retrievedLatestListID)
	})
	t.Run("Using holder profile store", func(t *testing.T) {
		holderProfileStore, err := storageProvider.OpenHolderProfileStore()
		require.NoError(t, err)

		testName := "TestName"

		holderProfile := vcsstorage.HolderProfile{
			DataProfile: vcsstorage.DataProfile{Name: testName},
		}

		err = holderProfileStore.Put(holderProfile)
		require.NoError(t, err)

		retrievedHolderProfile, err := holderProfileStore.Get(testName)
		require.NoError(t, err)
		require.Equal(t, holderProfile.Name, retrievedHolderProfile.Name)

		err = holderProfileStore.Delete(testName)
		require.NoError(t, err)

		retrievedHolderProfile, err = holderProfileStore.Get(testName)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedHolderProfile)
	})
	t.Run("Using issuer profile store", func(t *testing.T) {
		issuerProfileStore, err := storageProvider.OpenIssuerProfileStore()
		require.NoError(t, err)

		testName := "TestName"

		issuerProfile := vcsstorage.IssuerProfile{
			DataProfile: vcsstorage.DataProfile{Name: testName},
		}

		err = issuerProfileStore.Put(issuerProfile)
		require.NoError(t, err)

		retrievedIssuerProfile, err := issuerProfileStore.Get(testName)
		require.NoError(t, err)
		require.Equal(t, issuerProfile.Name, retrievedIssuerProfile.Name)

		err = issuerProfileStore.Delete(testName)
		require.NoError(t, err)

		retrievedIssuerProfile, err = issuerProfileStore.Get(testName)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedIssuerProfile)
	})
	t.Run("Using verifier profile store", func(t *testing.T) {
		verifierProfileStore, err := storageProvider.OpenVerifierProfileStore()
		require.NoError(t, err)

		testID := "TestID"

		verifierProfile := vcsstorage.VerifierProfile{
			ID: testID,
		}

		err = verifierProfileStore.Put(verifierProfile)
		require.NoError(t, err)

		retrievedVerifierProfile, err := verifierProfileStore.Get(testID)
		require.NoError(t, err)
		require.Equal(t, retrievedVerifierProfile.ID, retrievedVerifierProfile.ID)

		err = verifierProfileStore.Delete(testID)
		require.NoError(t, err)

		retrievedVerifierProfile, err = verifierProfileStore.Get(testID)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedVerifierProfile)
	})
}

func TestProvider_VCStore(t *testing.T) {
	t.Run("Fail to create MongoDB index", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL",
			mongodb.WithTimeout(1))
		require.NoError(t, err)

		storageProvider := mongodbvcsprovider.New(mongoDBProvider)

		vcStore, err := storageProvider.OpenVCStore()
		require.EqualError(t, err, "failed to create indexes in MongoDB collection:"+
			" failed to create indexes in MongoDB collection: server selection error:"+
			" context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
			"Type: Unknown }, ] }")
		require.Nil(t, vcStore)
	})
}

func TestProvider_CSLStore(t *testing.T) {
	t.Run("Fail to get CSL wrapper from MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL",
			mongodb.WithTimeout(1))
		require.NoError(t, err)

		storageProvider := mongodbvcsprovider.New(mongoDBProvider)

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		cslWrapper, err := cslStore.GetCSLWrapper("id")
		require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
			"context deadline exceeded, current topology: { Type: Unknown, Servers: "+
			"[{ Addr: badurl:27017, Type: Unknown }, ] }")
		require.Nil(t, cslWrapper)
	})
	t.Run("Fail to get latest list ID from MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL",
			mongodb.WithTimeout(1))
		require.NoError(t, err)

		storageProvider := mongodbvcsprovider.New(mongoDBProvider)

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		latestListID, err := cslStore.GetLatestListID()
		require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
			"context deadline exceeded, current topology: { Type: Unknown, Servers: "+
			"[{ Addr: badurl:27017, Type: Unknown }, ] }")
		require.Equal(t, -1, latestListID)
	})
}

func TestProvider_HolderProfileStore(t *testing.T) {
	t.Run("Fail to get holder profile from MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL",
			mongodb.WithTimeout(1))
		require.NoError(t, err)

		storageProvider := mongodbvcsprovider.New(mongoDBProvider)

		holderProfileStore, err := storageProvider.OpenHolderProfileStore()
		require.NoError(t, err)

		holderProfile, err := holderProfileStore.Get("name")
		require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
			"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
			"Type: Unknown }, ] }")
		require.Empty(t, holderProfile)
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
			"27017/tcp": {{HostIP: "", HostPort: "27017"}},
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
