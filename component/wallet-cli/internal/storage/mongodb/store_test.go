/*
Copyright Scoir Inc, Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/spi/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage/test"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage/mongodb"
)

const (
	mongoDBConnString    = "mongodb://localhost:27017"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTagV400 = "4.0.0"
	// dockerMongoDBTagV428 = "4.2.8"
	// dockerMongoDBTagV500 = "5.0.0"
)

// This should function the same as the default logger in the mongodb package.
// This is here just to increase code coverage by allowing us to exercise the WithLogger option.
type testLogger struct {
	logger *log.Logger
}

func (d *testLogger) Infof(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

func TestMongoDB_V4_0_0(t *testing.T) {
	startContainerAndDoAllTests(t, dockerMongoDBTagV400)
}

// func TestMongoDB_V4_2_8(t *testing.T) {
// 	startContainerAndDoAllTests(t, dockerMongoDBTagV428)
// }

// func TestMongoDB_V5_0_0(t *testing.T) {
// 	startContainerAndDoAllTests(t, dockerMongoDBTagV500)
// }

func TestProvider_New_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("BadConnString")
	require.EqualError(t, err, `failed to create a new MongoDB client: error parsing uri: `+
		`scheme must be "mongodb" or "mongodb+srv"`)
	require.Nil(t, provider)
}

func TestProvider_SetStoreConfig_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	_, err = provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = provider.SetStoreConfig("StoreName", storage.StoreConfiguration{TagNames: []string{"tagName1"}})
	require.EqualError(t, err, "failed to set indexes: failed to get existing indexed tag names: "+
		"failed to get list of indexes from MongoDB: server selection error: context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }") //nolint:lll
}

func TestProvider_GetStoreConfig_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStoreName")
	require.NoError(t, err)

	config, err := provider.GetStoreConfig("TestStoreName")
	require.EqualError(t, err, "failed to determine if the underlying database exists for teststorename: "+
		"server selection error: context deadline exceeded, current topology: { Type: Unknown, "+
		"Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Empty(t, config)
}

func TestProvider_Ping_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(time.Second))
	require.NoError(t, err)

	err = provider.Ping()
	require.Contains(t, err.Error(), "server selection error: context deadline exceeded, current topology:")
}

func TestStore_Put_Failure(t *testing.T) {
	t.Run("Deadline exceeded (server not reachable)", func(t *testing.T) {
		provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
		require.NoError(t, err)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)

		err = store.Put("key", []byte("value"))
		require.EqualError(t, err, "failed to run ReplaceOne command in MongoDB: server selection error: context "+
			"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	})
	t.Run("Invalid tags", func(t *testing.T) {
		// We only test for < and > here since the : case is handled in the common unit tests (commontest.TestAll)
		t.Run("Tag name contains <", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Name: "<"})
			require.EqualError(t, err, `"<" is an invalid tag name since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag value contains <", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Value: "<"})
			require.EqualError(t, err, `"<" is an invalid tag value since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag name contains >", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Name: ">"})
			require.EqualError(t, err, `">" is an invalid tag name since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag value contains >", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Value: ">"})
			require.EqualError(t, err, `">" is an invalid tag value since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag name used more than once", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Name: "SomeName"}, storage.Tag{Name: "SomeName"})
			require.EqualError(t, err, "tag name SomeName appears in more than one tag. "+
				"A single key-value pair cannot have multiple tags that share the same tag name")
		})
	})
}

func TestStore_PutAsJSON_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://ExampleURL")
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	mongoDBStore, ok := store.(*mongodb.Store)
	require.True(t, ok)

	err = mongoDBStore.PutAsJSON("key", "value")
	require.EqualError(t, err, "failed to unmarshal bytes into map: json: cannot unmarshal string into "+
		"Go value of type map[string]interface {}")
}

func TestStore_Get_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	value, err := store.Get("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, value)
}

func TestStore_GetTags_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	tags, err := store.GetTags("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
		"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
		"Type: Unknown }, ] }")
	require.Nil(t, tags)
}

func TestStore_GetBulk_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	values, err := store.GetBulk("key1", "key2")
	require.EqualError(t, err, "failed to run Find command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, values)
}

func TestStore_Delete_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = store.Delete("key1")

	require.Contains(t, err.Error(), "failed to run DeleteOne command in MongoDB: server selection error: "+
		"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown")
}

func TestStore_Batch_TimeoutFailure(t *testing.T) {
	storeName := test.RandomStoreName()

	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = store.Batch([]storage.Operation{{Key: "key"}})
	require.EqualError(t, err, "failed to run BulkWrite command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func startContainerAndDoAllTests(t *testing.T, dockerMongoDBTag string) {
	t.Helper()

	pool, mongoDBResource := startMongoDBContainer(t, dockerMongoDBTag)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	doAllTests(t, mongoDBConnString)
}

func doAllTests(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString, mongodb.WithLogger(&testLogger{
		logger: log.New(os.Stdout, "MongoDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
	}))
	require.NoError(t, err)

	test.TestAll(t, provider)
	testGetStoreConfigUnderlyingDatabaseCheck(t, connString)
	testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t, connString)
	testMultipleProvidersStoringSameDataAtTheSameTime(t, connString)
	testMultipleProvidersStoringSameBulkDataAtTheSameTime(t, connString)
	testCloseProviderTwice(t, connString)
	testQueryWithMultipleTags(t, connString)
	testQueryWithLessThanGreaterThanOperators(t, connString)
	testStoreJSONNeedingEscaping(t, connString)
	testBatchIsNewKeyError(t, connString)
	testPing(t, connString)
	testGetAsRawMap(t, connString)
	testGetBulkAsRawMap(t, connString)
	testCustomIndexAndQuery(t, connString)
	testDocumentReplacementAndMarshalling(t, connString)
	testBulkWrite(t, connString)
}

func testGetStoreConfigUnderlyingDatabaseCheck(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	storeName := test.RandomStoreName()

	// The MongoDB database shouldn't exist yet.
	config, err := provider.GetStoreConfig(storeName)
	require.Equal(t, true, errors.Is(storage.ErrStoreNotFound, err),
		"unexpected error or no error")
	require.Empty(t, config)

	_, err = provider.OpenStore(storeName)
	require.NoError(t, err)

	// Even though MongoDB defers creation of the underlying database until there is data put in or indexes are set,
	// we have code to ensure this method doesn't return an ErrStoreNotFound.
	config, err = provider.GetStoreConfig(storeName)
	require.NoError(t, err)
	require.Empty(t, config)

	// This will cause MongoDB to create the actual database.
	err = provider.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{"TagName1"}})
	require.NoError(t, err)

	// Now the underlying database should be found.
	config, err = provider.GetStoreConfig(storeName)
	require.NoError(t, err)
	require.Equal(t, "TagName1", config.TagNames[0])

	err = provider.Close()
	require.NoError(t, err)

	// Create a new Provider object.
	provider2, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider2.Close())
	}()

	// This method tells you how many Store objects are open in this Provider.
	// Since it's a new Provider, there shouldn't be any.
	openStores := provider2.GetOpenStores()
	require.Len(t, openStores, 0)

	// This will succeed since GetStoreConfig checks the underlying databases instead of the
	// in-memory Store objects (which will be empty).
	// If we hadn't called SetStoreConfig before, then this would return an ErrStoreNotFound.
	config, err = provider2.GetStoreConfig(storeName)
	require.NoError(t, err)
	require.Equal(t, "TagName1", config.TagNames[0])

	// The call above should not have created a new Store object.
	openStores = provider2.GetOpenStores()
	require.Len(t, openStores, 0)

	// As mentioned above, MongoDB defers creating databases until there is data put in or indexes are set.
	// The code above triggered database creation by creating indexes. Below we will do the same type of test, but this
	// time we create the database by storing data.
	storeName2 := test.RandomStoreName()

	store, err := provider2.OpenStore(storeName2)
	require.NoError(t, err)

	// Even though MongoDB defers creation of the underlying database until there is data put in or indexes are set,
	// we have code to ensure this method doesn't return an ErrStoreNotFound.
	config, err = provider2.GetStoreConfig(storeName2)
	require.NoError(t, err)
	require.Empty(t, config)

	// This will cause MongoDB to create the actual database.
	err = store.Put("key", []byte("value"))
	require.NoError(t, err)

	// Create a new Provider object.
	provider3, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider3.Close())
	}()

	// This will succeed since GetStoreConfig checks the underlying databases instead of the
	// in-memory Store objects (which will be empty).
	// If we hadn't called Put before, then this would return an ErrStoreNotFound.
	config, err = provider3.GetStoreConfig(storeName2)
	require.NoError(t, err)
	require.Empty(t, config.TagNames)
}

func testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := test.RandomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*10), mongodb.WithMaxRetries(10), mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errSetStoreConfig := providers[i].SetStoreConfig(storeName,
				storage.StoreConfiguration{TagNames: []string{
					"TagName1", "TagName2", "TagName3", "TagName4",
					"TagName5", "TagName6", "TagName7", "TagName8",
					"TagName9", "TagName10", "TagName11", "TagName12",
					"TagName13", "TagName14", "TagName15", "TagName16",
					"TagName17", "TagName18", "TagName19", "TagName20",
					"TagName21", "TagName22", "TagName23", "TagName24",
					"TagName25", "TagName26", "TagName27", "TagName28",
					"TagName29", "TagName30", "TagName31", "TagName32",
				}})
			require.NoError(t, errSetStoreConfig)

			// Close the Store as soon as possible in order to free up resources for other threads.
			require.NoError(t, openStores[i].Close())
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	storeConfig, err := providers[0].GetStoreConfig(storeName)
	require.NoError(t, err)

	require.Len(t, storeConfig.TagNames, 32)

	for i := 0; i < len(storeConfig.TagNames); i++ {
		require.Equal(t, fmt.Sprintf("TagName%d", i+1), storeConfig.TagNames[i])
	}
}

func testMultipleProvidersStoringSameDataAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := test.RandomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*10), mongodb.WithMaxRetries(10), mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	type sampleStruct struct {
		Entry1 string `json:"entry1"`
		Entry2 string `json:"entry2"`
		Entry3 string `json:"entry3"`
	}

	sampleData := sampleStruct{
		Entry1: "value1",
		Entry2: "value2",
		Entry3: "value3",
	}

	sampleDataBytes, err := json.Marshal(sampleData)
	require.NoError(t, err)

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errPut := openStores[i].Put("key", sampleDataBytes)
			require.NoError(t, errPut)
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	value, err := openStores[0].Get("key")
	require.NoError(t, err)

	var retrievedData sampleStruct

	err = json.Unmarshal(value, &retrievedData)
	require.NoError(t, err)

	require.Equal(t, sampleData.Entry1, retrievedData.Entry1)
	require.Equal(t, sampleData.Entry2, retrievedData.Entry2)
	require.Equal(t, sampleData.Entry3, retrievedData.Entry3)
}

func testMultipleProvidersStoringSameBulkDataAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := test.RandomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*5), mongodb.WithMaxRetries(10), mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	type sampleStruct struct {
		Entry1 string `json:"entry1"`
		Entry2 string `json:"entry2"`
		Entry3 string `json:"entry3"`
	}

	sampleData1 := sampleStruct{
		Entry1: "value1",
		Entry2: "value2",
		Entry3: "value3",
	}

	sampleData1Bytes, err := json.Marshal(sampleData1)
	require.NoError(t, err)

	sampleData2 := sampleStruct{
		Entry1: "value4",
		Entry2: "value5",
		Entry3: "value6",
	}

	sampleData2Bytes, err := json.Marshal(sampleData2)
	require.NoError(t, err)

	sampleData3 := sampleStruct{
		Entry1: "value7",
		Entry2: "value8",
		Entry3: "value9",
	}

	sampleData3Bytes, err := json.Marshal(sampleData3)
	require.NoError(t, err)

	operations := []storage.Operation{
		{Key: "key1", Value: sampleData1Bytes},
		{Key: "key2", Value: sampleData2Bytes},
		{Key: "key3", Value: sampleData3Bytes},
	}

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errBatch := openStores[i].Batch(operations)
			require.NoError(t, errBatch)

			// Close the Store as soon as possible in order to free up resources for other threads.
			require.NoError(t, openStores[i].Close())
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	values, err := openStores[0].GetBulk("key1", "key2", "key3")
	require.NoError(t, err)

	require.Len(t, values, 3)

	var retrievedData1 sampleStruct

	err = json.Unmarshal(values[0], &retrievedData1)
	require.NoError(t, err)

	require.Equal(t, sampleData1.Entry1, retrievedData1.Entry1)
	require.Equal(t, sampleData1.Entry2, retrievedData1.Entry2)
	require.Equal(t, sampleData1.Entry3, retrievedData1.Entry3)

	var retrievedData2 sampleStruct

	err = json.Unmarshal(values[1], &retrievedData2)
	require.NoError(t, err)

	require.Equal(t, sampleData2.Entry1, retrievedData2.Entry1)
	require.Equal(t, sampleData2.Entry2, retrievedData2.Entry2)
	require.Equal(t, sampleData2.Entry3, retrievedData2.Entry3)

	var retrievedData3 sampleStruct

	err = json.Unmarshal(values[2], &retrievedData3)
	require.NoError(t, err)

	require.Equal(t, sampleData3.Entry1, retrievedData3.Entry1)
	require.Equal(t, sampleData3.Entry2, retrievedData3.Entry2)
	require.Equal(t, sampleData3.Entry3, retrievedData3.Entry3)
}

func testCloseProviderTwice(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStore1")
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStore2")
	require.NoError(t, err)

	require.NoError(t, provider.Close())
	require.NoError(t, provider.Close()) // Should succeed, even if called repeatedly.
}

func testQueryWithMultipleTags(t *testing.T, connString string) { //nolint: gocyclo // test file
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	keysToPut, valuesToPut, tagsToPut := getTestData()

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = provider.SetStoreConfig(storeName,
		storage.StoreConfiguration{TagNames: []string{
			tagsToPut[0][0].Name,
			tagsToPut[0][1].Name,
			tagsToPut[0][2].Name,
			tagsToPut[0][3].Name,
			tagsToPut[0][4].Name,
		}})
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	test.PutData(t, store, keysToPut, valuesToPut, tagsToPut)

	t.Run("Both pairs are tag names + values - 3 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Breed:GoldenRetriever&&NumLegs:4&&EarType:Floppy",
			"NumLegs:4&&EarType:Floppy&&Breed:GoldenRetriever", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[0], keysToPut[3], keysToPut[4]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[3], valuesToPut[4]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[3], tagsToPut[4]}
		expectedTotalItemsCount := 3

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 2 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Breed:GoldenRetriever&&Personality:Calm",
			"Personality:Calm&&Breed:GoldenRetriever", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[3], keysToPut[4]}
		expectedValues := [][]byte{valuesToPut[3], valuesToPut[4]}
		expectedTags := [][]storage.Tag{tagsToPut[3], tagsToPut[4]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 1 value found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Personality:Shy&&EarType:Pointy",
			"EarType:Pointy&&Personality:Shy", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[1]}
		expectedValues := [][]byte{valuesToPut[1]}
		expectedTags := [][]storage.Tag{tagsToPut[1]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 0 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Personality:Crazy&&EarType:Pointy",
			"EarType:Pointy&&Personality:Crazy", // Should be equivalent to the above expression
		}

		expectedTotalItemsCount := 0

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, nil, nil, nil, expectedTotalItemsCount, false)
			}
		}
	})
	t.Run("First pair is a tag name + value, second is a tag name only - 1 value found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"EarType:Pointy&&Nickname",
			"Nickname&&EarType:Pointy", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[2]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
			}
		}
	})
	t.Run("First pair is a tag name + value, second is a tag name only - 0 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"EarType:Pointy&&CoatType",
			"CoatType&&EarType:Pointy", // Should be equivalent to the above expression
		}

		expectedTotalItemsCount := 0

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator2(t, iterator, nil, nil, nil, expectedTotalItemsCount, false)
			}
		}
	})
}

func testQueryWithLessThanGreaterThanOperators(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	keysToPut, valuesToPut, tagsToPut := getTestData()

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = provider.SetStoreConfig(storeName,
		storage.StoreConfiguration{TagNames: []string{
			tagsToPut[0][0].Name,
			tagsToPut[0][1].Name,
			tagsToPut[0][2].Name,
			tagsToPut[0][3].Name,
			tagsToPut[0][4].Name,
			tagsToPut[0][5].Name,
		}})
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	test.PutData(t, store, keysToPut, valuesToPut, tagsToPut)

	t.Run("Less than or equal to", func(t *testing.T) {
		queryExpression := "Age<=2"

		expectedKeys := []string{keysToPut[0], keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[1], tagsToPut[2]}
		expectedTotalItemsCount := 3

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
		}
	})
	t.Run("Less than", func(t *testing.T) {
		queryExpression := "Age<2"

		expectedKeys := []string{keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[1], tagsToPut[2]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
		}
	})
	t.Run("Greater than or equal to", func(t *testing.T) {
		queryExpression := "Age>=2"

		expectedKeys := []string{keysToPut[0], keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[3]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[3]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
		}
	})
	t.Run("Greater than", func(t *testing.T) {
		queryExpression := "Age>2"

		expectedKeys := []string{keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[3]}
		expectedTags := [][]storage.Tag{tagsToPut[3]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount, false)
		}
	})
	t.Run("Tag value is not a valid integer", func(t *testing.T) {
		iterator, err := store.Query("TagName>ThisIsNotAnInteger")
		require.EqualError(t, err, "invalid query format. when using any one of the <=, <, >=, > operators, "+
			"the immediate value on the right side side must be a valid integer: strconv.Atoi: parsing "+
			`"ThisIsNotAnInteger": invalid syntax`)
		require.Nil(t, iterator)
	})
}

func testStoreJSONNeedingEscaping(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	store, err := provider.OpenStore(test.RandomStoreName())
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		t.Run("One simple key-value pair", func(t *testing.T) {
			type simpleType struct {
				OneDotHere string `json:"oneDotHere.,omitempty"`
			}

			testValue := simpleType{OneDotHere: "SomeValue"}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey1"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueBytesRetrieved, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved simpleType

			err = json.Unmarshal(testValueBytesRetrieved, &testValueRetrieved)
			require.NoError(t, err)

			require.Equal(t, testValue.OneDotHere, testValueRetrieved.OneDotHere)
		})
		t.Run("Two key-value pairs, no escaping needed", func(t *testing.T) {
			type testType struct {
				NoDotHere  string `json:"noDotHere,omitempty"`
				DotInValue string `json:"dotInValue,omitempty"`
			}

			testValue := testType{
				NoDotHere:  "SomeValue",
				DotInValue: "DotHereButItDoesn'tNeedEscaping.",
			}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey2"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueRetrievedBytes, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved testType

			err = json.Unmarshal(testValueRetrievedBytes, &testValueRetrieved)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(testValueRetrieved, testValue),
				"Value retrieved from storage not the same as what was put in originally")
		})
		t.Run("Two key-value pairs, only one needs escaping", func(t *testing.T) {
			type testType struct {
				OneDotHere string `json:"oneDotHere.,omitempty"`
				DotInValue string `json:"dotInValue,omitempty"`
			}

			testValue := testType{
				OneDotHere: "SomeValue",
				DotInValue: "DotHereButItDoesn'tNeedEscaping.",
			}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey3"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueRetrievedBytes, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved testType

			err = json.Unmarshal(testValueRetrievedBytes, &testValueRetrieved)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(testValueRetrieved, testValue),
				"Value retrieved from storage not the same as what was put in originally")
		})
		t.Run("Nested object", func(t *testing.T) {
			type testTypeInner struct {
				SeveralDotsHere string `json:".several.Dots.Here.,omitempty"`
			}

			type testType struct {
				OneDotHere                string        `json:"oneDotHere.,omitempty"`
				NoDotHere                 string        `json:"noDotHere,omitempty"`
				NestedObjectWithDotInName testTypeInner `json:"nestedObject.,omitempty"`
			}

			testValue := testType{
				OneDotHere:                "SomeValue",
				NoDotHere:                 "AlsoSomeValue",
				NestedObjectWithDotInName: testTypeInner{SeveralDotsHere: "SomeNestedValue"},
			}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey4"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueRetrievedBytes, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved testType

			err = json.Unmarshal(testValueRetrievedBytes, &testValueRetrieved)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(testValueRetrieved, testValue),
				"Value retrieved from storage not the same as what was put in originally")
		})
		t.Run("Array", func(t *testing.T) {
			type testTypeInner struct {
				SeveralDotsHere string `json:".several.Dots.Here.,omitempty"`
			}

			type testType struct {
				OneDotHere           string          `json:"oneDotHere.,omitempty"`
				NoDotHere            string          `json:"noDotHere,omitempty"`
				ArrayOfNestedObjects []testTypeInner `json:"nestedObject.,omitempty"`
			}

			testValue := testType{
				OneDotHere: "SomeValue",
				NoDotHere:  "AlsoSomeValue",
				ArrayOfNestedObjects: []testTypeInner{
					{SeveralDotsHere: "SomeNestedValue1"},
					{SeveralDotsHere: "SomeNestedValue2"},
				},
			}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey5"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueRetrievedBytes, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved testType

			err = json.Unmarshal(testValueRetrievedBytes, &testValueRetrieved)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(testValueRetrieved, testValue),
				"Value retrieved from storage not the same as what was put in originally")
		})
		t.Run("Big, complex object with many different types and lots of nesting and arrays", func(t *testing.T) {
			type leaf struct {
				NoDotHere       string  `json:"noDotHere,omitempty"`
				OneDotHere      bool    `json:"oneDotHere.,omitempty"`
				SeveralDotsHere float64 `json:".several.Dots.Here.,omitempty"`
			}

			type smallerBranch struct {
				OneDotHere      string  `json:"oneDotHere.,omitempty"`
				SeveralDotsHere float32 `json:".several.Dots.Here.,omitempty"`
				Leaf            leaf    `json:"leaf...,omitempty"`
			}

			type biggerBranch struct {
				SeveralDotsHere int             `json:".several.Dots.Here.,omitempty"`
				NoDotHere       string          `json:"noDotHere,omitempty"`
				SmallerBranch   smallerBranch   `json:"smallerBranch,omitempty"`
				SmallerBranches []smallerBranch `json:"smaller.Branches,omitempty"`
			}

			type treeRoot struct {
				OneDotHere           string       `json:"oneDotHere.,omitempty"`
				NoDotHere            string       `json:"noDotHere,omitempty"`
				AlsoNoDotHere        int          `json:"alsoNoDotHere,omitempty"`
				DeeplyNestedObject1  biggerBranch `json:"deeply.NestedObject1,omitempty"`
				ArrayOfNestedObjects []leaf       `json:"arrayOfNestedObjects.,omitempty"`
				DeeplyNestedObject2  biggerBranch `json:"deeplyNestedObject2,omitempty"`
			}

			testValue := treeRoot{
				OneDotHere:    "SomeValue1",
				NoDotHere:     "SomeValue2",
				AlsoNoDotHere: 3,
				DeeplyNestedObject1: biggerBranch{
					SeveralDotsHere: -4,
					NoDotHere:       "SomeValue3",
					SmallerBranch: smallerBranch{
						OneDotHere:      "SomeValue4",
						SeveralDotsHere: 0.65,
						Leaf: leaf{
							NoDotHere:       "SomeValue5",
							OneDotHere:      true,
							SeveralDotsHere: -17.6789323,
						},
					},
					SmallerBranches: []smallerBranch{
						{
							OneDotHere:      "SomeValue5",
							SeveralDotsHere: 100.654,
							Leaf: leaf{
								NoDotHere:       "SomeValue6",
								OneDotHere:      false,
								SeveralDotsHere: 101,
							},
						},
						{
							OneDotHere:      "SomeValue7",
							SeveralDotsHere: 1,
							Leaf: leaf{
								NoDotHere:       "SomeValue8",
								OneDotHere:      false,
								SeveralDotsHere: 1994,
							},
						},
					},
				},
				ArrayOfNestedObjects: []leaf{
					{
						NoDotHere:       "SomeValue9",
						OneDotHere:      true,
						SeveralDotsHere: 3.14159,
					},
					{
						NoDotHere:       "Some.Value10",
						OneDotHere:      false,
						SeveralDotsHere: 589,
					},
				},
			}

			testValueBytes, err := json.Marshal(testValue)
			require.NoError(t, err)

			testKey := "TestKey6"

			err = store.Put(testKey, testValueBytes)
			require.NoError(t, err)

			testValueRetrievedBytes, err := store.Get(testKey)
			require.NoError(t, err)

			var testValueRetrieved treeRoot

			err = json.Unmarshal(testValueRetrievedBytes, &testValueRetrieved)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(testValueRetrieved, testValue),
				"Value retrieved from storage not the same as what was put in originally")
		})
	})
	t.Run("Attempt to store JSON with a key containing the backtick (`) character", func(t *testing.T) {
		testValueUsingBacktickInRootLevel := `{"keyWithBacktick` + "`" + `":"Value"}`

		t.Run("Put", func(t *testing.T) {
			t.Run("Invalid character in root level", func(t *testing.T) {
				err := store.Put("TestKey4", []byte(testValueUsingBacktickInRootLevel))
				require.EqualError(t, err, "JSON keys cannot have \"`\" characters within them. "+
					"Invalid key: keyWithBacktick`")
			})
			t.Run("Invalid character in nested object", func(t *testing.T) {
				testValueUsingBacktickInNestedLevel := `{"nestedData":{"keyWithBacktick` + "`" + `":"Value"}}`

				err := store.Put("TestKey4", []byte(testValueUsingBacktickInNestedLevel))
				require.EqualError(t, err, "JSON keys cannot have \"`\" characters within them. "+
					"Invalid key: keyWithBacktick`")
			})
			t.Run("Invalid character in object in array", func(t *testing.T) {
				testValueUsingBacktickInNestedLevel := `{"arrayData":[{"keyWithBacktick` + "`" + `":"Value"}]}`

				err := store.Put("TestKey4", []byte(testValueUsingBacktickInNestedLevel))
				require.EqualError(t, err, "JSON keys cannot have \"`\" characters within them. "+
					"Invalid key: keyWithBacktick`")
			})
		})
		t.Run("Batch - invalid character in root level", func(t *testing.T) {
			operations := []storage.Operation{{Key: "TestKey4", Value: []byte(testValueUsingBacktickInRootLevel)}}
			err := store.Batch(operations)
			require.EqualError(t, err, "JSON keys cannot have \"`\" characters within them. "+
				"Invalid key: keyWithBacktick`")
		})
	})
}

func testBatchIsNewKeyError(t *testing.T, connString string) {
	t.Helper()

	storeName := test.RandomStoreName()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = store.Put("SomeKey", []byte("SomeValue"))
	require.NoError(t, err)

	operations := []storage.Operation{
		{Key: "SomeKey", Value: []byte("SomeUpdatedValue"), PutOptions: &storage.PutOptions{IsNewKey: true}},
	}

	err = store.Batch(operations)

	expectedErrMsgPrefix := "failed to perform batch operations after 4 attempts: duplicate key. Either an " +
		"InsertOne model is being used for a key that already exists in the database, or, if " +
		"using MongoDB 4.0.0, then this may be a transient error due to another call storing data under the same " +
		"key at the same time. Underlying error message: bulk write exception: write errors: [E11000 duplicate key " +
		"error"

	gotExpectedError := strings.HasPrefix(err.Error(), expectedErrMsgPrefix)

	require.True(t, gotExpectedError, fmt.Sprintf("received unexpected error. Expected the error message to "+
		`start with "%s", but the error was "%s"`, expectedErrMsgPrefix, err.Error()))
}

func testPing(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	err = provider.Ping()
	require.NoError(t, err)
}

func testGetAsRawMap(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	mongoDBStore, ok := store.(*mongodb.Store)
	require.True(t, ok)

	testData := map[string]interface{}{
		"field1": "value1",
		"field2": int64(2),
		"field3": true,
	}

	err = mongoDBStore.PutAsJSON("TestKey", testData)
	require.NoError(t, err)

	retrievedTestData, err := mongoDBStore.GetAsRawMap("TestKey")
	require.NoError(t, err)

	// The retrieved test data should be the same as the input test data, except that there's an _id field now.

	testData["_id"] = "TestKey"

	require.True(t, reflect.DeepEqual(testData, retrievedTestData),
		"unexpected retrieved test data")
}

func testGetBulkAsRawMap(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	var ok bool

	mongoDBStore, ok := store.(*mongodb.Store)
	require.True(t, ok)

	_, err = mongoDBStore.GetBulkAsRawMap("TestKey1", "")
	require.EqualError(t, err, "key cannot be empty")

	testData1 := map[string]interface{}{
		"field1": "value1",
		"field2": int64(2),
		"field3": true,
	}

	testData2 := map[string]interface{}{
		"field1": "value1",
		"field2": int64(2),
		"field3": true,
	}

	require.NoError(t, mongoDBStore.PutAsJSON("TestKey1", testData1))
	require.NoError(t, mongoDBStore.PutAsJSON("TestKey2", testData2))

	retrievedTestData, err := mongoDBStore.GetBulkAsRawMap("TestKey1", "TestKey2")
	require.NoError(t, err)
	require.Len(t, retrievedTestData, 2)

	// The retrieved test data should be the same as the input test data, except that there's an _id field now.
	testData1["_id"] = "TestKey1"
	testData2["_id"] = "TestKey2"

	require.True(t, reflect.DeepEqual(testData1, retrievedTestData[0]), "unexpected retrieved test data")
	require.True(t, reflect.DeepEqual(testData2, retrievedTestData[1]), "unexpected retrieved test data")
}

func testCustomIndexAndQuery(t *testing.T, connString string) {
	t.Helper()
	t.Run("Using individual PutAsJSON calls", func(t *testing.T) {
		t.Run("Without query options", func(t *testing.T) {
			doCustomIndexAndQueryTest(t, connString, false)
		})
		t.Run("Using query options", func(t *testing.T) {
			doCustomIndexAndQueryTest(t, connString, false, options.Find().SetBatchSize(2))
		})
	})
	t.Run("Using BulkWrite call", func(t *testing.T) {
		t.Run("Without query options", func(t *testing.T) {
			doCustomIndexAndQueryTest(t, connString, true)
		})
		t.Run("Using query options", func(t *testing.T) {
			doCustomIndexAndQueryTest(t, connString, true, options.Find().SetBatchSize(2))
		})
	})
	t.Run("Store not found", func(t *testing.T) {
		provider, err := mongodb.NewProvider(connString)
		require.NoError(t, err)

		err = provider.CreateCustomIndexes("NonExistentStore", mongo.IndexModel{})
		require.Equal(t, err, storage.ErrStoreNotFound)
	})
	t.Run("Fail to create indexes", func(t *testing.T) {
		provider, err := mongodb.NewProvider(connString)
		require.NoError(t, err)

		storeName := test.RandomStoreName()

		_, err = provider.OpenStore(storeName)
		require.NoError(t, err)

		err = provider.CreateCustomIndexes(storeName, mongo.IndexModel{})
		require.EqualError(t, err, "failed to create indexes in MongoDB collection: failed to create "+
			"indexes in MongoDB collection: index model keys cannot be nil")
	})
}

func doCustomIndexAndQueryTest(t *testing.T, connString string, useBatch bool, opts ...*options.FindOptions) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	var ok bool

	mongoDBStore, ok := store.(*mongodb.Store)
	require.True(t, ok)

	valuesToStore := generateJSONTestData()

	storeDataWithoutWrapping(t, mongoDBStore, valuesToStore, useBatch)

	createCustomIndexForCustomQueryTests(t, provider, storeName)

	t.Run("Querying for one attribute", func(t *testing.T) {
		filter := bson.D{
			{
				Key:   "indexed.attributes.name",
				Value: "Name1",
			},
		}

		iterator, err := mongoDBStore.QueryCustom(filter, opts...)
		require.NoError(t, err)
		require.NotEmpty(t, iterator)

		expectedKeys := []string{"Document1", "Document2"}

		verifyExpectedIterator2(t, iterator, expectedKeys, valuesToStore, nil, 2, true)
	})
	t.Run("Querying for two attributes (AND operator)", func(t *testing.T) {
		filter := bson.D{
			{
				Key:   "indexed.attributes.name",
				Value: "Name1",
			},
			{
				Key:   "indexed.attributes.value",
				Value: "Value1",
			},
		}

		iterator, err := mongoDBStore.QueryCustom(filter, opts...)
		require.NoError(t, err)
		require.NotEmpty(t, iterator)

		expectedKeys := []string{"Document1"}
		expectedValues := [][]byte{valuesToStore[0]}

		verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, nil, 1, true)
	})
	t.Run("Querying for two attributes (OR operator)", func(t *testing.T) {
		filter := bson.D{
			{
				Key: "$or",
				Value: bson.A{
					bson.D{{Key: "indexed.attributes.name", Value: "Name3"}},
					bson.D{{Key: "indexed.attributes.name", Value: "Name4"}},
				},
			},
		}
		iterator, err := mongoDBStore.QueryCustom(filter, opts...)
		require.NoError(t, err)
		require.NotEmpty(t, iterator)

		expectedKeys := []string{"Document1", "Document3"}
		expectedValues := [][]byte{valuesToStore[0], valuesToStore[2]}

		verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, nil, 2, true)
	})
	t.Run("Querying for multiple attributes (mix of AND and OR operators)", func(t *testing.T) {
		filter := bson.D{
			{
				Key: "$or",
				Value: bson.A{
					bson.D{
						{Key: "indexed.attributes.name", Value: "Name1"},
						{Key: "indexed.attributes.value", Value: "Value2"},
					},
					bson.D{{Key: "indexed.attributes.name", Value: "Name4"}},
				},
			},
		}
		iterator, err := mongoDBStore.QueryCustom(filter, opts...)
		require.NoError(t, err)
		require.NotEmpty(t, iterator)

		expectedKeys := []string{"Document2", "Document3"}
		expectedValues := [][]byte{valuesToStore[1], valuesToStore[2]}

		verifyExpectedIterator2(t, iterator, expectedKeys, expectedValues, nil, 2, true)
	})
}

func testDocumentReplacementAndMarshalling(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	t.Run("Put method - switching between wrapped data types", func(t *testing.T) {
		storeName := test.RandomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)

		mongoDBStore, ok := store.(*mongodb.Store)
		require.True(t, ok)

		type testStruct struct {
			FieldNameWithCapitalLetters string `json:"fieldNameWithCapitalLetters"`
			FieldNameWithOmitEmpty      string `json:"fieldNameWithOmitEmpty,omitempty"`
		}

		testStruct1 := testStruct{
			FieldNameWithCapitalLetters: "SomeValue",
			FieldNameWithOmitEmpty:      "SomeOtherValue",
		}

		testStruct1Bytes, err := json.Marshal(testStruct1)
		require.NoError(t, err)

		err = mongoDBStore.Put("TestKey", testStruct1Bytes)
		require.NoError(t, err)

		testStruct1.FieldNameWithOmitEmpty = ""

		err = mongoDBStore.Put("TestKey", []byte{1, 2, 3})
		require.NoError(t, err)

		valueAsMap, err := mongoDBStore.GetAsRawMap("TestKey")
		require.NoError(t, err)

		_, found := valueAsMap["doc"]
		require.False(t, found, "stored document was not replaced properly")

		_, found = valueAsMap["bin"]
		require.True(t, found, "stored document was not replaced properly")
	})
	t.Run("PutAsJSON - test JSON struct tags", func(t *testing.T) {
		storeName := test.RandomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)

		mongoDBStore, ok := store.(*mongodb.Store)
		require.True(t, ok)

		type testStruct struct {
			FieldNameWithCapitalLetters string `json:"fieldNameWithCapitalLetters"`
			FieldNameWithOmitEmpty      string `json:"fieldNameWithOmitEmpty,omitempty"`
		}

		testStruct1 := testStruct{
			FieldNameWithCapitalLetters: "SomeValue",
			FieldNameWithOmitEmpty:      "SomeOtherValue",
		}

		err = mongoDBStore.PutAsJSON("TestKey", testStruct1)
		require.NoError(t, err)

		testStruct1.FieldNameWithOmitEmpty = ""

		err = mongoDBStore.PutAsJSON("TestKey", testStruct1)
		require.NoError(t, err)

		valueAsMap, err := mongoDBStore.GetAsRawMap("TestKey")
		require.NoError(t, err)

		_, found := valueAsMap["fieldnamewithcapitalletters"]
		require.False(t, found, "field name casing was not maintained")

		_, found = valueAsMap["fieldNameWithCapitalLetters"]
		require.True(t, found, "field name missing")

		_, found = valueAsMap["FieldNameWithOmitEmpty"]
		require.False(t, found, "empty field was not omitted")
	})
}

func TestCreateMongoDBFindOptions(t *testing.T) {
	s := &mongodb.Store{}

	t.Run("isJSONQuery = false", func(t *testing.T) {
		opts := s.CreateMongoDBFindOptions([]storage.QueryOption{
			storage.WithPageSize(1000),
			storage.WithInitialPageNum(10),
			storage.WithSortOrder(&storage.SortOptions{
				Order:   storage.SortDescending,
				TagName: "tag1",
			}),
		}, false)
		require.NotNil(t, opts)
		require.NotNil(t, opts.BatchSize)
		require.Equal(t, int32(1000), *opts.BatchSize)
		require.NotNil(t, opts.Skip)
		require.Equal(t, int64(10000), *opts.Skip)
		require.NotNil(t, opts.Sort)

		sortOpts, ok := opts.Sort.(primitive.D)
		require.True(t, ok)
		require.Len(t, sortOpts, 1)
		require.Equal(t, "tags.tag1", sortOpts[0].Key)
		require.Equal(t, -1, sortOpts[0].Value)
	})

	t.Run("isJSONQuery = true", func(t *testing.T) {
		opts := s.CreateMongoDBFindOptions([]storage.QueryOption{
			storage.WithSortOrder(&storage.SortOptions{
				Order:   storage.SortAscending,
				TagName: "tag1",
			}),
		}, true)
		require.NotNil(t, opts)
		require.NotNil(t, opts.Sort)

		sortOpts, ok := opts.Sort.(primitive.D)
		require.True(t, ok)
		require.Len(t, sortOpts, 1)
		require.Equal(t, "tag1", sortOpts[0].Key)
		require.Equal(t, 1, sortOpts[0].Value)
	})
}

func testBulkWrite(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	storeName := test.RandomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	mongoDBStore, ok := store.(*mongodb.Store)
	require.True(t, ok)

	type testDataType struct {
		StringValue string `json:"stringValue,omitempty"`
		IntValue    int    `json:"intValue,omitempty"`
	}

	data1 := testDataType{
		StringValue: "String1",
		IntValue:    1,
	}

	preparedData1, err := mongodb.PrepareDataForBSONStorage(data1)
	require.NoError(t, err)

	data2 := testDataType{
		StringValue: "String2",
		IntValue:    2,
	}

	preparedData2, err := mongodb.PrepareDataForBSONStorage(data2)
	require.NoError(t, err)

	models := []mongo.WriteModel{
		mongo.NewInsertOneModel().SetDocument(preparedData1),
		mongo.NewInsertOneModel().SetDocument(preparedData2),
	}

	err = mongoDBStore.BulkWrite(models)
	require.NoError(t, err)

	filter := bson.D{
		{
			Key: "$or",
			Value: bson.A{
				bson.D{{Key: "stringValue", Value: "String1"}},
				bson.D{{Key: "stringValue", Value: "String2"}},
			},
		},
	}

	iterator, err := mongoDBStore.QueryCustom(filter)
	require.NoError(t, err)

	more, err := iterator.Next()
	require.NoError(t, err)
	require.True(t, more)

	retrievedData1, err := iterator.ValueAsRawMap()
	require.NoError(t, err)
	require.Equal(t, "String1", retrievedData1["stringValue"])
	require.Equal(t, int64(1), retrievedData1["intValue"])

	more, err = iterator.Next()
	require.NoError(t, err)
	require.True(t, more)

	retrievedData2, err := iterator.ValueAsRawMap()
	require.NoError(t, err)
	require.Equal(t, "String2", retrievedData2["stringValue"])
	require.Equal(t, int64(2), retrievedData2["intValue"])

	more, err = iterator.Next()
	require.NoError(t, err)
	require.False(t, more)

	data1New := testDataType{
		StringValue: "String1_New",
		IntValue:    11,
	}

	preparedData1New, err := mongodb.PrepareDataForBSONStorage(data1New)
	require.NoError(t, err)

	data2New := testDataType{
		StringValue: "String2_New",
		IntValue:    22,
	}

	preparedData2New, err := mongodb.PrepareDataForBSONStorage(data2New)
	require.NoError(t, err)

	models = []mongo.WriteModel{
		mongo.NewReplaceOneModel().SetFilter(bson.M{"stringValue": "String1"}).SetReplacement(preparedData1New),
		mongo.NewReplaceOneModel().SetFilter(bson.M{"stringValue": "String2"}).SetReplacement(preparedData2New),
	}

	err = mongoDBStore.BulkWrite(models)
	require.NoError(t, err)

	filter = bson.D{
		{
			Key: "$or",
			Value: bson.A{
				bson.D{{Key: "stringValue", Value: "String1_New"}},
				bson.D{{Key: "stringValue", Value: "String2_New"}},
			},
		},
	}

	iterator, err = mongoDBStore.QueryCustom(filter)
	require.NoError(t, err)

	more, err = iterator.Next()
	require.NoError(t, err)
	require.True(t, more)

	retrievedData1New, err := iterator.ValueAsRawMap()
	require.NoError(t, err)
	require.Equal(t, "String1_New", retrievedData1New["stringValue"])
	require.Equal(t, int64(11), retrievedData1New["intValue"])

	more, err = iterator.Next()
	require.NoError(t, err)
	require.True(t, more)

	retrievedData2New, err := iterator.ValueAsRawMap()
	require.NoError(t, err)
	require.Equal(t, "String2_New", retrievedData2New["stringValue"])
	require.Equal(t, int64(22), retrievedData2New["intValue"])

	more, err = iterator.Next()
	require.NoError(t, err)
	require.False(t, more)

	models = []mongo.WriteModel{
		mongo.NewDeleteOneModel().SetFilter(bson.M{"stringValue": "String1_New"}),
		mongo.NewDeleteOneModel().SetFilter(bson.M{"stringValue": "DoesNotExist"}),
	}

	err = mongoDBStore.BulkWrite(models)
	require.NoError(t, err)

	filter = bson.D{
		{
			Key: "$or",
			Value: bson.A{
				bson.D{{Key: "stringValue", Value: "String1_New"}},
				bson.D{{Key: "stringValue", Value: "String2_New"}},
			},
		},
	}

	iterator, err = mongoDBStore.QueryCustom(filter)
	require.NoError(t, err)

	more, err = iterator.Next()
	require.NoError(t, err)
	require.True(t, more)

	retrievedData2NewAgain, err := iterator.ValueAsRawMap()
	require.NoError(t, err)
	require.Equal(t, "String2_New", retrievedData2NewAgain["stringValue"])
	require.Equal(t, int64(22), retrievedData2NewAgain["intValue"])

	more, err = iterator.Next()
	require.NoError(t, err)
	require.False(t, more)
}

func getTestData() (testKeys []string, testValues [][]byte, testTags [][]storage.Tag) {
	testKeys = []string{
		"Cassie",
		"Luna",
		"Miku",
		"Amber",
		"Brandy",
	}

	testValues = [][]byte{
		[]byte("is a big, young dog"),
		[]byte("is a small dog"),
		[]byte("is a fluffy dog (also small)"),
		[]byte("is a big, old dog"),
		[]byte("is a big dog of unknown age (but probably old)"),
	}

	testTags = [][]storage.Tag{
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Playful"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Nickname", Value: "Miss"},
			{Name: "Age", Value: "2"},
		},
		{
			{Name: "Breed", Value: "Schweenie"},
			{Name: "Personality", Value: "Shy"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "Pomchi"},
			{Name: "Personality", Value: "Outgoing"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Nickname", Value: "Fluffball"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Age", Value: "14"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
		},
	}

	return testKeys, testValues, testTags
}

func createCustomIndexForCustomQueryTests(t *testing.T, provider *mongodb.Provider, storeName string) {
	t.Helper()

	indexOptions := options.Index()
	indexOptions.SetName("Custom Index")

	model := mongo.IndexModel{
		Keys: bson.D{
			{Key: "indexed.attributes.name", Value: 1},
			{Key: "indexed.attributes.value", Value: 1},
		},
		Options: indexOptions,
	}

	err := provider.CreateCustomIndexes(storeName, model)
	require.NoError(t, err)
}

func storeDataWithoutWrapping(t *testing.T, store *mongodb.Store, values [][]byte, useBatch bool) {
	t.Helper()

	if useBatch {
		insertOneModels := make([]mongo.WriteModel, len(values))

		for i, value := range values {
			var valueAsMap map[string]interface{}

			err := json.Unmarshal(value, &valueAsMap)
			require.NoError(t, err)

			preparedData, err := mongodb.PrepareDataForBSONStorage(valueAsMap)
			require.NoError(t, err)

			preparedData["_id"] = fmt.Sprintf("Document%d", i+1)

			insertOneModels[i] = mongo.NewInsertOneModel().SetDocument(preparedData)
		}

		err := store.BulkWrite(insertOneModels)
		require.NoError(t, err)

		return
	}

	for i, value := range values {
		var valueAsMap map[string]interface{}

		err := json.Unmarshal(value, &valueAsMap)
		require.NoError(t, err)

		err = store.PutAsJSON(fmt.Sprintf("Document%d", i+1), valueAsMap)
		require.NoError(t, err)
	}
}

func generateJSONTestData() [][]byte {
	value1Bytes := []byte(`{
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "Name1",
        "value": "Value1"
      }, {
        "name": "Name2",
        "value": "Value1",
	    "anotherField": "Something"
      },
	  {
        "name": "Name3",
        "value": "Value1",
	    "aBoolField": true
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	value2Bytes := []byte(`{
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "Name1",
        "value": "Value2"
      }, {
        "name": "Name2",
        "value": "Value2"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	value3Bytes := []byte(`{
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "Name4",
        "value": "Value1"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	return [][]byte{value1Bytes, value2Bytes, value3Bytes}
}

// expectedKeys, expectedValues, and expectedTags are with respect to the query's page settings.
// Since iterator.TotalItems' count is not affected by page settings, expectedTotalItemsCount must be passed in and
// can't be determined by looking at the length of expectedKeys, expectedValues, nor expectedTags.
func verifyExpectedIterator2(t *testing.T, actualResultsItr storage.Iterator, expectedKeys []string,
	expectedValues [][]byte, expectedTags [][]storage.Tag, expectedTotalItemsCount int, isCustomQueryTest bool) {
	t.Helper()

	if !isCustomQueryTest && (len(expectedValues) != len(expectedKeys) || len(expectedTags) != len(expectedKeys)) {
		require.FailNow(t,
			"Invalid test case. Expected keys, values and tags slices must be the same length.")
	}

	verifyIteratorAnyOrder2(t, actualResultsItr, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount,
		isCustomQueryTest)
}

func verifyIteratorAnyOrder2(t *testing.T, actualResultsItr storage.Iterator, //nolint:gocognit, gocyclo // test file
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]storage.Tag, expectedTotalItemsCount int,
	isCustomQueryTest bool) {
	t.Helper()

	var dataChecklist struct {
		keys     []string
		values   [][]byte
		tags     [][]storage.Tag
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.tags = expectedTags
	dataChecklist.received = make([]bool, len(expectedKeys))

	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	if !moreResultsToCheck && len(expectedKeys) != 0 {
		require.FailNow(t, "query unexpectedly returned no results")
	}

	for moreResultsToCheck {
		dataReceivedCount := 0

		for _, received := range dataChecklist.received {
			if received {
				dataReceivedCount++
			}
		}

		if dataReceivedCount == len(dataChecklist.received) {
			require.FailNow(t, "iterator contains more results than expected")
		}

		var itrErr error
		receivedKey, itrErr := actualResultsItr.Key()
		require.NoError(t, itrErr)

		var receivedValueMap map[string]interface{}

		var receivedValue []byte

		if isCustomQueryTest {
			actualMongoDBResultsItr, ok := actualResultsItr.(mongodb.Iterator)
			require.True(t, ok)

			receivedValueMap, itrErr = actualMongoDBResultsItr.ValueAsRawMap()
			require.NoError(t, itrErr)
		} else {
			receivedValue, itrErr = actualResultsItr.Value()
			require.NoError(t, itrErr)
		}

		receivedTags, itrErr := actualResultsItr.Tags()
		require.NoError(t, itrErr)

		for i := 0; i < len(dataChecklist.keys); i++ {
			if receivedKey == dataChecklist.keys[i] { //nolint:nestif // test file
				if isCustomQueryTest {
					if isEquivalentJSON(t, receivedValueMap, dataChecklist.values[i]) {
						dataChecklist.received[i] = true

						break
					}
				} else {
					if string(receivedValue) == string(dataChecklist.values[i]) {
						if test.EqualTags(receivedTags, dataChecklist.tags[i]) {
							dataChecklist.received[i] = true

							break
						}
					}
				}
			}
		}

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)
	}

	count, errTotalItems := actualResultsItr.TotalItems()
	require.NoError(t, errTotalItems)
	require.Equal(t, expectedTotalItemsCount, count)

	err = actualResultsItr.Close()
	require.NoError(t, err)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func isEquivalentJSON(t *testing.T, receivedMapFromMongoDB map[string]interface{}, originalValue []byte) bool {
	t.Helper()

	var originalValueAsMap map[string]interface{}

	err := json.Unmarshal(originalValue, &originalValueAsMap)
	require.NoError(t, err)

	// Add the _id field that we expect MongoDB to add so the two are comparable.
	// Then, remarshal so we can compare to see if we got equivalent JSON.

	originalValueAsMap["_id"] = receivedMapFromMongoDB["_id"]

	remarshalledOriginalValue, err := json.Marshal(originalValueAsMap)
	require.NoError(t, err)

	remarshalledReceivedValue, err := json.Marshal(receivedMapFromMongoDB)
	require.NoError(t, err)

	return string(remarshalledReceivedValue) == string(remarshalledOriginalValue)
}

func startMongoDBContainer(t *testing.T, dockerMongoDBTag string) (*dctest.Pool, *dctest.Resource) {
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
