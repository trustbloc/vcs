/*
Copyright Scoir Inc, Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mongodb implements a storage provider conforming to the storage interface in aries-framework-go.
// It is compatible with MongoDB v4.0.0, v4.2.8, and v5.0.0. It is also compatible with Amazon DocumentDB 4.0.0.
// It may be compatible with other versions, but they haven't been tested.
package mongodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/trustbloc/kms-go/spi/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	defaultTimeout                         = time.Second * 10
	defaultMaxIndexCreationConflictRetries = 3

	invalidTagName = `"%s" is an invalid tag name since it contains one or more of the ` +
		`following substrings: ":", "<=", "<", ">=", ">"`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more of the ` +
		`following substrings: ":", "<=", "<", ">=", ">"`
	failCreateIndexesInMongoDBCollection = "failed to create indexes in MongoDB collection: %w"

	equalsExpressionTagNameOnlyLength     = 1
	equalsExpressionTagNameAndValueLength = 2
	lessThanGreaterThanExpressionLength
)

var (
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"It must be in the following format: " +
		"TagName:TagValue or TagName1:TagValue1&&TagName2:TagValue2. Tag values are optional. If using tag values," +
		"<=, <, >=, or > may be used in place of the : to match a range of tag values")

	// errUnmarshalBytesIntoMap is used in the convertMarshalledValueToMap function to allow the generateDataWrapper
	// function to differentiate between an unmarshal failure and other types of failures.
	errUnmarshalBytesIntoMap = errors.New("failed to unmarshal bytes into map")
)

type logger interface {
	Infof(msg string, args ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (d *defaultLogger) Infof(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

type closer func(storeName string)

type dataWrapper struct {
	Key  string                 `bson:"_id"`
	Doc  map[string]interface{} `bson:"doc,omitempty"`
	Str  string                 `bson:"str,omitempty"`
	Bin  []byte                 `bson:"bin,omitempty"`
	Tags map[string]interface{} `bson:"tags,omitempty"`
}

// Option represents an option for a MongoDB Provider.
type Option func(opts *Provider)

// WithDBPrefix is an option for adding a prefix to all created database names.
// No prefix will be used by default.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// WithLogger is an option for specifying a custom logger.
// The standard Golang logger will be used by default.
func WithLogger(logger logger) Option {
	return func(opts *Provider) {
		opts.logger = logger
	}
}

// WithTimeout is an option for specifying the timeout for all calls to MongoDB.
// The timeout is 10 seconds by default.
func WithTimeout(timeout time.Duration) Option {
	return func(opts *Provider) {
		opts.timeout = timeout
	}
}

// WithMaxRetries is an option for specifying how many retries are allowed when there are certain transient errors
// from MongoDB. These transient errors can happen in two situations:
//  1. An index conflict error when setting indexes via the SetStoreConfig method from multiple MongoDB Provider
//     objects that look at the same stores (which might happen if you have multiple running instances of a service).
//  2. If you're using MongoDB 4.0.0 (or DocumentDB 4.0.0), a "dup key" type of error when calling Store.Put or
//     Store.Batch from multiple MongoDB Provider objects that look at the same stores.
//
// maxRetries must be > 0. If not set (or set to an invalid value), it will default to 3.
func WithMaxRetries(maxRetries uint64) Option {
	return func(opts *Provider) {
		opts.maxRetries = maxRetries
	}
}

// WithTimeBetweenRetries is an option for specifying how long to wait between retries when
// there are certain transient errors from MongoDB. These transient errors can happen in two situations:
//  1. An index conflict error when setting indexes via the SetStoreConfig method from multiple MongoDB Provider
//     objects that look at the same stores (which might happen if you have multiple running instances of a service).
//  2. If you're using MongoDB 4.0.0 (or DocumentDB 4.0.0), a "dup key" type of error when calling Store.Put or
//     Store.Batch multiple times in parallel on the same key.
//
// Defaults to two seconds if not set.
func WithTimeBetweenRetries(timeBetweenRetries time.Duration) Option {
	return func(opts *Provider) {
		opts.timeBetweenRetries = timeBetweenRetries
	}
}

// Provider represents a MongoDB/DocumentDB implementation of the storage.Provider interface.
type Provider struct {
	client             *mongo.Client
	openStores         map[string]*Store
	dbPrefix           string
	lock               sync.RWMutex
	logger             logger
	timeout            time.Duration
	maxRetries         uint64
	timeBetweenRetries time.Duration
}

// NewProvider instantiates a new MongoDB Provider.
// connString is a connection string as defined in https://docs.mongodb.com/manual/reference/connection-string/.
// Note that options supported by the Go Mongo driver (and the names of them) may differ from the documentation above.
// Check the Go Mongo driver (go.mongodb.org/mongo-driver/mongo) to make sure the options you're specifying
// are supported and will be captured correctly.
// If using DocumentDB, the retryWrites option must be set to false in the connection string (retryWrites=false) in
// order for it to work.
func NewProvider(connString string, opts ...Option) (*Provider, error) {
	p := &Provider{openStores: map[string]*Store{}}

	setOptions(opts, p)

	client, err := mongo.NewClient(mongooptions.Client().ApplyURI(connString))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new MongoDB client: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	err = client.Connect(ctxWithTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	p.client = client

	return p, nil
}

// OpenStore opens a Store with the given name and returns a handle.
// If the underlying database for the given name has never been created before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	name = strings.ToLower(p.dbPrefix + name)

	p.lock.Lock()
	defer p.lock.Unlock()

	openStore, ok := p.openStores[name]
	if ok {
		return openStore, nil
	}

	newStore := &Store{
		// The storage interface doesn't have the concept of a nested database, so we have no real use for the
		// collection abstraction MongoDB uses. Since we have to use at least one collection, we keep the collection
		// name as short as possible to avoid hitting the index size limit.
		coll:               p.getCollectionHandle(name),
		name:               name,
		logger:             p.logger,
		close:              p.removeStore,
		timeout:            p.timeout,
		maxRetries:         p.maxRetries,
		timeBetweenRetries: p.timeBetweenRetries,
	}

	p.openStores[name] = newStore

	return newStore, nil
}

// SetStoreConfig sets the configuration on a Store.
// Indexes are created based on the tag names in config. This allows the Store.Query method to operate faster.
// Existing tag names/indexes in the Store that are not in the config passed in here will be removed.
// The Store must already be open in this provider from a prior call to OpenStore. The name parameter cannot be blank.
func (p *Provider) SetStoreConfig(storeName string, config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	storeName = strings.ToLower(p.dbPrefix + storeName)

	openStore, found := p.openStores[storeName]
	if !found {
		return storage.ErrStoreNotFound
	}

	var attemptsMade int

	err := backoff.Retry(func() error {
		attemptsMade++

		err := p.setIndexes(openStore, config)
		if err != nil {
			// If there are multiple MongoDB Providers trying to set Store configurations, it's possible
			// to get an error. In cases where those multiple MongoDB providers are trying
			// to set the exact same Store configuration, retrying here allows them to succeed without failing
			// unnecessarily.
			if isIndexConflictErrorMessage(err) {
				p.logger.Infof("[Store name: %s] Attempt %d - error while setting indexes. "+
					"This can happen if multiple MongoDB providers set the store configuration at the "+
					"same time. If there are remaining retries, this operation will be tried again after %s. "+
					"Underlying error message: %s",
					storeName, attemptsMade, p.timeBetweenRetries.String(), err.Error())

				// The error below isn't marked using backoff.Permanent, so it'll only be seen if the retry limit
				// is reached.
				return fmt.Errorf("failed to set indexes after %d attempts. This storage provider may "+
					"need to be started with a higher max retry limit and/or higher time between retries. "+
					"Underlying error message: %w", attemptsMade, err)
			}

			// This is an unexpected error.
			return backoff.Permanent(fmt.Errorf("failed to set indexes: %w", err))
		}

		p.logger.Infof("[Store name: %s] Attempt %d - successfully set indexes.",
			storeName, attemptsMade)

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(p.timeBetweenRetries), p.maxRetries))
	if err != nil {
		return err
	}

	return nil
}

// GetStoreConfig gets the current Store configuration.
// If the underlying database for the given name has never been
// created by a call to OpenStore at some point, then an error wrapping ErrStoreNotFound will be returned. This
// method will not open a Store in the Provider.
// If name is blank, then an error will be returned.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	name = strings.ToLower(p.dbPrefix + name)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	databaseNames, err := p.client.ListDatabaseNames(ctxWithTimeout, bson.D{{Key: "name", Value: name}})
	if err != nil {
		return storage.StoreConfiguration{}, fmt.Errorf("failed to determine if the underlying database "+
			"exists for %s: %w", name, err)
	}

	if len(databaseNames) == 0 {
		// MongoDB defers the creation of the collection until the first actual storage call.
		// In the case where someone calls OpenStore and then GetStoreConfig immediately, MongoDB will report that
		// the database doesn't exist, but logically from the point of view of this object it does indeed exist,
		// so we shouldn't return an ErrStoreNotFound.
		_, exists := p.openStores[name]
		if !exists {
			return storage.StoreConfiguration{}, storage.ErrStoreNotFound
		}

		return storage.StoreConfiguration{}, nil
	}

	existingIndexedTagNames, err := p.getExistingIndexedTagNames(p.getCollectionHandle(name))
	if err != nil {
		return storage.StoreConfiguration{}, fmt.Errorf("failed to get existing indexed tag names: %w", err)
	}

	return storage.StoreConfiguration{TagNames: existingIndexedTagNames}, nil
}

// GetOpenStores returns all Stores currently open in this Provider.
func (p *Provider) GetOpenStores() []storage.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]storage.Store, len(p.openStores))

	var counter int

	for _, openStore := range p.openStores {
		openStores[counter] = openStore
		counter++
	}

	return openStores
}

// Close closes all stores created under this Store provider.
func (p *Provider) Close() error {
	p.lock.RLock()

	openStoresSnapshot := make([]*Store, len(p.openStores))

	var counter int

	for _, openStore := range p.openStores {
		openStoresSnapshot[counter] = openStore
		counter++
	}
	p.lock.RUnlock()

	for _, openStore := range openStoresSnapshot {
		err := openStore.Close()
		if err != nil {
			return fmt.Errorf(`failed to close open store with name "%s": %w`, openStore.name, err)
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	err := p.client.Disconnect(ctxWithTimeout)
	if err != nil {
		if err.Error() == "client is disconnected" {
			return nil
		}

		return fmt.Errorf("failed to disconnect from MongoDB: %w", err)
	}

	return nil
}

// Ping verifies whether the MongoDB client can successfully connect to the deployment specified by
// the connection string used in the NewProvider call.
func (p *Provider) Ping() error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	return p.client.Ping(ctxWithTimeout, nil)
}

// CreateCustomIndexes allows for any custom indexes to be created in MongoDB based on the given index models.
// Intended for use alongside the Store.PutAsJSON, Store.GetAsRawMap and Iterator.ValueAsRawMap methods.
func (p *Provider) CreateCustomIndexes(storeName string, models ...mongo.IndexModel) error {
	storeName = strings.ToLower(p.dbPrefix + storeName)

	store, exists := p.openStores[storeName]
	if !exists {
		return storage.ErrStoreNotFound
	}

	err := p.createIndexes(store, models)
	if err != nil {
		return fmt.Errorf(failCreateIndexesInMongoDBCollection, err)
	}

	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.openStores[name]
	if ok {
		delete(p.openStores, name)
	}
}

const (
	collectionPrefix = "cli_mongo_generic-"
)

func (p *Provider) getCollectionHandle(name string) *mongo.Collection {
	return p.client.Database(name).Collection("c")
}

func (p *Provider) setIndexes(openStore *Store, config storage.StoreConfiguration) error {
	tagNamesNeedIndexCreation, err := p.determineTagNamesNeedIndexCreation(openStore, config)
	if err != nil {
		return err
	}

	if len(tagNamesNeedIndexCreation) > 0 {
		models := make([]mongo.IndexModel, len(tagNamesNeedIndexCreation))

		for i, tagName := range tagNamesNeedIndexCreation {
			indexOptions := mongooptions.Index()
			indexOptions.SetName(tagName)

			models[i] = mongo.IndexModel{
				Keys:    bson.D{{Key: fmt.Sprintf("tags.%s", tagName), Value: 1}},
				Options: indexOptions,
			}
		}

		err = p.createIndexes(openStore, models)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) determineTagNamesNeedIndexCreation(openStore *Store,
	config storage.StoreConfiguration) ([]string, error) {
	existingIndexedTagNames, err := p.getExistingIndexedTagNames(openStore.coll)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing indexed tag names: %w", err)
	}

	tagNameIndexesAlreadyConfigured := make(map[string]struct{})

	for _, existingIndexedTagName := range existingIndexedTagNames {
		var existingTagIsInNewConfig bool

		for _, tagName := range config.TagNames {
			if existingIndexedTagName == tagName {
				existingTagIsInNewConfig = true
				tagNameIndexesAlreadyConfigured[tagName] = struct{}{}

				p.logger.Infof("[Store name (includes prefix, if any): %s] Skipping index creation for %s "+
					"since the index already exists.", openStore.name, tagName)

				break
			}
		}

		// If the new Store configuration doesn't have the existing index (tag) defined, then we will delete it
		if !existingTagIsInNewConfig {
			ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)

			_, errDrop := openStore.coll.Indexes().DropOne(ctxWithTimeout, existingIndexedTagName)
			if errDrop != nil {
				cancel()

				return nil, fmt.Errorf("failed to remove index for %s: %w", existingIndexedTagName, errDrop)
			}

			cancel()
		}
	}

	var tagNamesNeedIndexCreation []string

	for _, tag := range config.TagNames {
		_, indexAlreadyCreated := tagNameIndexesAlreadyConfigured[tag]
		if !indexAlreadyCreated {
			tagNamesNeedIndexCreation = append(tagNamesNeedIndexCreation, tag)
		}
	}

	return tagNamesNeedIndexCreation, nil
}

func (p *Provider) getExistingIndexedTagNames(collection *mongo.Collection) ([]string, error) {
	indexesCursor, err := p.getIndexesCursor(collection)
	if err != nil {
		return nil, err
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	var results []bson.M

	err = indexesCursor.All(ctxWithTimeout, &results)
	if err != nil {
		return nil, fmt.Errorf("failed to get all results from indexes cursor")
	}

	if results == nil {
		return nil, nil
	}

	existingIndexedTagNames := make([]string, len(results)-1)

	var counter int

	for _, result := range results {
		indexNameRaw, exists := result["name"]
		if !exists {
			return nil, errors.New(`index data is missing the "key" field`)
		}

		indexName, ok := indexNameRaw.(string)
		if !ok {
			return nil, errors.New(`index name is of unexpected type`)
		}

		// The _id_ index is a built-in index in MongoDB. It wasn't one that can be set using SetStoreConfig,
		// so we omit it here.
		if indexName == "_id_" {
			continue
		}

		existingIndexedTagNames[counter] = indexName

		counter++
	}

	return existingIndexedTagNames, nil
}

func (p *Provider) getIndexesCursor(collection *mongo.Collection) (*mongo.Cursor, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	indexesCursor, err := collection.Indexes().List(ctxWithTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get list of indexes from MongoDB: %w", err)
	}

	return indexesCursor, nil
}

func (p *Provider) createIndexes(openStore *Store, models []mongo.IndexModel) error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	_, err := openStore.coll.Indexes().CreateMany(ctxWithTimeout, models)
	if err != nil {
		return fmt.Errorf(failCreateIndexesInMongoDBCollection, err)
	}

	return nil
}

// Store represents a MongoDB/DocumentDB implementation of the storage.Store interface.
type Store struct {
	name               string
	logger             logger
	coll               *mongo.Collection
	close              closer
	timeout            time.Duration
	maxRetries         uint64
	timeBetweenRetries time.Duration
}

// Put stores the key + value pair along with the (optional) tags.
// If tag values are valid int32 or int64, they will be stored as integers in MongoDB, so we can sort numerically later.
// If storing a JSON value, then any key names (within the JSON) cannot contain "`" characters. This is because we
// use it as a replacement for "." characters, which are not valid in DocumentDB as JSON key names.
func (s *Store) Put(key string, value []byte, tags ...storage.Tag) error {
	err := validatePutInput(key, value, tags)
	if err != nil {
		return err
	}

	data, err := generateDataWrapper(key, value, tags)
	if err != nil {
		return err
	}

	return s.executeReplaceOneCommand(key, data)
}

// PutAsJSON stores the given key and value.
// Value must be a struct with exported fields and proper json tags or a map. It will get marshalled before being
// converted to the format needed by the MongoDB driver. Value is stored directly in a MongoDB document without
// wrapping, with key being used as the _id field. Data stored this way must be retrieved using the GetAsRawMap method.
// When querying for this data, use the QueryCustom method, and when retrieving from the iterator use the
// iterator.ValueAsRawMap method.
func (s *Store) PutAsJSON(key string, value interface{}) error {
	data, err := PrepareDataForBSONStorage(value)
	if err != nil {
		return err
	}

	return s.executeReplaceOneCommand(key, data)
}

// Get fetches the value associated with the given key.
// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (s *Store) Get(key string) ([]byte, error) {
	result, err := s.runFindOneCommand(key)
	if err != nil {
		return nil, err
	}

	_, value, err := getKeyAndValueFromMongoDBResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from MongoDB result: %w", err)
	}

	return value, nil
}

// GetAsRawMap fetches the full MongoDB JSON document stored with the given id (_id field in MongoDB).
// The document is returned as a map (which includes the _id field).
func (s *Store) GetAsRawMap(id string) (map[string]interface{}, error) {
	result, err := s.runFindOneCommand(id)
	if err != nil {
		return nil, err
	}

	return getValueAsRawMapFromMongoDBResult(result)
}

// GetTags fetches all tags associated with the given key.
// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (s *Store) GetTags(key string) ([]storage.Tag, error) {
	result, err := s.runFindOneCommand(key)
	if err != nil {
		return nil, err
	}

	tags, err := getTagsFromMongoDBResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from MongoDB result: %w", err)
	}

	return tags, nil
}

// GetBulk fetches the values associated with the given keys.
// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
// Depending on the implementation, this method may be faster than calling Get for each key individually.
// If any of the given keys are empty, then an error will be returned.
// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
func (s *Store) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	for _, key := range keys {
		if key == "" {
			return nil, errors.New("key cannot be empty")
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cursor, err := s.coll.Find(ctxWithTimeout, bson.M{"_id": bson.D{
		{Key: "$in", Value: keys},
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to run Find command in MongoDB: %w", err)
	}

	allValues, err := s.collectBulkGetResults(keys, cursor)
	if err != nil {
		return nil, err
	}

	return allValues, nil
}

// GetBulkAsRawMap fetches the values associated with the given keys and returns the documents (as maps).
// If no data exists under a given key, then nil is returned for that value. It is not considered an error.
// Depending on the implementation, this method may be faster than calling Get for each key individually.
// If any of the given keys are empty, then an error will be returned.
func (s *Store) GetBulkAsRawMap(keys ...string) ([]map[string]interface{}, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	for _, key := range keys {
		if key == "" {
			return nil, errors.New("key cannot be empty")
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cursor, err := s.coll.Find(ctxWithTimeout, bson.M{"_id": bson.D{
		{Key: "$in", Value: keys},
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to run Find command in MongoDB: %w", err)
	}

	allValues, err := s.collectBulkGetResultsAsRawMap(keys, cursor)
	if err != nil {
		return nil, err
	}

	return allValues, nil
}

// Query does a query for data as defined by the documentation in storage.Store (the interface).
// This implementation also supports querying for data tagged with multiple tag name + value pairs (using AND logic).
// To do this, separate the tag name + value pairs using &&. You can still omit one or both of the tag values
// in order to indicate that you want any data tagged with the tag name, regardless of tag value.
// For example, TagName1:TagValue1&&TagName2:TagValue2:...:TagNameN:TagValueN will return only data that has been
// tagged with all pairs. See testQueryWithMultipleTags in store_test.go for more examples of querying using multiple
// tags. If the tag you're using has tag values that are integers, then you can use the <, <=, >, >= operators instead
// of : to get a range of matching data. For example, TagName>3 will return any data tagged with a tag named TagName
// that has a value greater than 3.
// It's recommended to set up an index using the Provider.SetStoreConfig method in order to speed up queries.
// TODO (#146) Investigate compound indexes and see if they may be useful for queries with sorts and/or for queries
//
//	with multiple tags.
func (s *Store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	if expression == "" {
		return &iterator{}, errInvalidQueryExpressionFormat
	}

	filter, err := PrepareFilter(strings.Split(expression, "&&"), false)
	if err != nil {
		return nil, err
	}

	findOptions := s.CreateMongoDBFindOptions(options, false)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cursor, err := s.coll.Find(ctxWithTimeout, filter, findOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to run Find command in MongoDB: %w", err)
	}

	return &iterator{
		cursor:  cursor,
		coll:    s.coll,
		filter:  filter,
		timeout: s.timeout,
	}, nil
}

// Iterator represents a MongoDB/DocumentDB implementation of the storage.Iterator interface.
type Iterator interface {
	storage.Iterator

	ValueAsRawMap() (map[string]interface{}, error)
}

// QueryCustom queries for data using the MongoDB find command. The given filter and options are passed directly to the
// driver. Intended for use alongside the Provider.CreateCustomIndexes, Store.PutAsJSON, and
// Iterator.ValueAsRawMap methods.
func (s *Store) QueryCustom(filter interface{}, options ...*mongooptions.FindOptions) (Iterator, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cursor, err := s.coll.Find(ctxWithTimeout, filter, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to run Find command in MongoDB: %w", err)
	}

	return &iterator{
		cursor:      cursor,
		coll:        s.coll,
		filter:      filter,
		timeout:     s.timeout,
		customQuery: true,
	}, nil
}

// Delete deletes the value (and all tags) associated with key.
func (s *Store) Delete(key string) error {
	if key == "" {
		return errors.New("key is mandatory")
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err := s.coll.DeleteOne(ctxWithTimeout, bson.M{"_id": key})
	if err != nil {
		return fmt.Errorf("failed to run DeleteOne command in MongoDB: %w", err)
	}

	return err
}

// Batch performs multiple Put and/or Delete operations in order.
// If storing a JSON value, then any key names (within the JSON) cannot contain "`" characters. This is because we
// use it as a replacement for "." characters, which are not valid in DocumentDB as JSON key names.
// Put operations can be sped up by making use of the storage.PutOptions.IsNewKey option for any keys that you know
// for sure do not already exist in the database. If this option is used and the key does exist, then this method will
// return an error.
func (s *Store) Batch(operations []storage.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	for _, operation := range operations {
		if operation.Key == "" {
			return errors.New("key cannot be empty")
		}
	}

	models := make([]mongo.WriteModel, len(operations))

	var atLeastOneInsertOneModel bool

	for i, operation := range operations {
		var err error

		var isInsertOneModel bool

		models[i], isInsertOneModel, err = generateModelForBulkWriteCall(operation)
		if err != nil {
			return err
		}

		if isInsertOneModel {
			atLeastOneInsertOneModel = true
		}
	}

	return s.executeBulkWriteCommand(models, atLeastOneInsertOneModel, nil)
}

// BulkWrite executes the mongoDB BulkWrite command using the given WriteModels and BulkWriteOptions.
func (s *Store) BulkWrite(models []mongo.WriteModel, opts ...*mongooptions.BulkWriteOptions) error {
	var atLeastOneInsertOneModel bool

	for _, model := range models {
		_, isInsertOneModel := model.(*mongo.InsertOneModel)
		if isInsertOneModel {
			atLeastOneInsertOneModel = true

			break
		}
	}

	return s.executeBulkWriteCommand(models, atLeastOneInsertOneModel, opts)
}

// Flush doesn't do anything since this store type doesn't queue values.
func (s *Store) Flush() error {
	return nil
}

// Close removes this Store from the parent Provider's list of open stores. It does not close this Store's connection
// to the database, since it's shared across stores. To close the connection you must call Provider.Close.
func (s *Store) Close() error {
	s.close(s.name)

	return nil
}

func (s *Store) executeReplaceOneCommand(key string, value interface{}) error {
	opts := mongooptions.ReplaceOptions{}
	opts.SetUpsert(true)

	var attemptsMade int

	return backoff.Retry(func() error {
		attemptsMade++

		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()

		_, err := s.coll.ReplaceOne(ctxWithTimeout, bson.M{"_id": key}, value, &opts)
		if err != nil {
			// If using MongoDB 4.0.0 (or DocumentDB 4.0.0), and this is called multiple times in parallel on the
			// same key, then it's possible to get a transient error here. We need to retry in this case.
			if strings.Contains(err.Error(), "duplicate key error collection") {
				s.logger.Infof(`[Store name: %s] Attempt %d - error while storing data under key "%s". `+
					"This can happen if there are multiple calls in parallel to Store data under the same key. "+
					"If there are remaining retries, this operation will be tried again after %s. "+
					"Underlying error message: %s", s.name, attemptsMade, key, s.timeBetweenRetries.String(),
					err.Error())

				// The error below isn't marked using backoff.Permanent, so it'll only be seen if the retry limit
				// is reached.
				return fmt.Errorf("failed to store data after %d attempts. This storage provider may "+
					"need to be started with a higher max retry limit and/or higher time between retries. "+
					"Underlying error message: %w", attemptsMade, err)
			}

			// This is an unexpected error.
			return backoff.Permanent(fmt.Errorf("failed to run ReplaceOne command in MongoDB: %w", err))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(s.timeBetweenRetries), s.maxRetries))
}

func (s *Store) runFindOneCommand(id string) (*mongo.SingleResult, error) {
	if id == "" {
		return nil, errors.New("key is mandatory")
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	result := s.coll.FindOne(ctxWithTimeout, bson.M{"_id": id})
	if errors.Is(result.Err(), mongo.ErrNoDocuments) {
		return nil, storage.ErrDataNotFound
	} else if result.Err() != nil {
		return nil, fmt.Errorf("failed to run FindOne command in MongoDB: %w", result.Err())
	}

	return result, nil
}

func (s *Store) collectBulkGetResults(keys []string, cursor *mongo.Cursor) ([][]byte, error) {
	allValues := make([][]byte, len(keys))

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	for cursor.Next(ctxWithTimeout) {
		key, value, err := getKeyAndValueFromMongoDBResult(cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get value from MongoDB result: %w", err)
		}

		for i := 0; i < len(keys); i++ {
			if key == keys[i] {
				allValues[i] = value

				break
			}
		}
	}

	return allValues, nil
}

func (s *Store) collectBulkGetResultsAsRawMap(keys []string, cursor *mongo.Cursor) ([]map[string]interface{}, error) {
	allValues := make([]map[string]interface{}, len(keys))

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	for cursor.Next(ctxWithTimeout) {
		key, value, err := getKeyAndRawMapFromMongoDBResult(cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get value from MongoDB result: %w", err)
		}

		for i := 0; i < len(keys); i++ {
			if key == keys[i] {
				allValues[i] = value

				break
			}
		}
	}

	return allValues, nil
}

func (s *Store) executeBulkWriteCommand(models []mongo.WriteModel, atLeastOneInsertOneModel bool,
	opts []*mongooptions.BulkWriteOptions) error {
	var attemptsMade int

	return backoff.Retry(func() error {
		attemptsMade++

		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()

		_, err := s.coll.BulkWrite(ctxWithTimeout, models, opts...)
		if err != nil {
			// If using MongoDB 4.0.0 (or DocumentDB 4.0.0), and this is called multiple times in parallel on the
			// same key(s), then it's possible to get a transient error here. We need to retry in this case.
			if strings.Contains(err.Error(), "duplicate key error collection") {
				// If the IsNewKey optimization is being used, then we generate a more informative log message and
				// error.

				var errorReason string

				var errDuplicateKey error

				if atLeastOneInsertOneModel {
					errorReason = "Either an InsertOne model is being used for a key that " +
						"already exists in the database, or, if using MongoDB 4.0.0, then this may be a transient " +
						"error due to another call storing data under the same key at the same time."

					// The "ErrDuplicateKey" error from the storage interface is used to indicate a failure due to
					// the IsNewKey flag being used for a key that isn't new. A caller can check for this using
					// errors.Is().
					errDuplicateKey = storage.ErrDuplicateKey
				} else {
					errorReason = "If using MongoDB 4.0.0, then this may be a transient " +
						"error due to another call storing data under the same key at the same time."

					// While the text of this error matches the text from storage.ErrDuplicateKey, we don't use that
					// specific error here since the meaning of storage.ErrDuplicateKey is specifically tied to the
					// usage of the IsNewKey optimization.
					errDuplicateKey = errors.New("duplicate key")
				}

				s.logger.Infof("[Store name: %s] Attempt %d - %s while performing batch "+
					" operations. %s If there are remaining retries, the batch operations will be tried again "+
					"after %s. Underlying error message: %s", s.name, attemptsMade, storage.ErrDuplicateKey,
					errorReason, s.timeBetweenRetries.String(), err.Error())

				// The error below isn't marked using backoff.Permanent, so it'll only be seen if the retry limit
				// is reached.
				return fmt.Errorf("failed to perform batch operations after %d attempts: %w. "+
					"%s Underlying error message: %s", attemptsMade, errDuplicateKey, errorReason,
					err.Error())
			}

			// This is an unexpected error.
			return backoff.Permanent(fmt.Errorf("failed to run BulkWrite command in MongoDB: %w", err))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(s.timeBetweenRetries), s.maxRetries))
}

// CreateMongoDBFindOptions converts the given storage options into MongoDB options.
func (s *Store) CreateMongoDBFindOptions(options []storage.QueryOption, isJSONQuery bool) *mongooptions.FindOptions {
	queryOptions := getQueryOptions(options)

	findOptions := mongooptions.Find()

	if queryOptions.PageSize > 0 || queryOptions.InitialPageNum > 0 {
		findOptions = mongooptions.Find()

		findOptions.SetBatchSize(int32(queryOptions.PageSize))

		if queryOptions.PageSize > 0 && queryOptions.InitialPageNum > 0 {
			findOptions.SetSkip(int64(queryOptions.InitialPageNum * queryOptions.PageSize))
		}
	}

	if queryOptions.SortOptions != nil {
		mongoDBSortOrder := 1
		if queryOptions.SortOptions.Order == storage.SortDescending {
			mongoDBSortOrder = -1
		}

		var key string

		if isJSONQuery {
			key = queryOptions.SortOptions.TagName
		} else {
			key = fmt.Sprintf("tags.%s", queryOptions.SortOptions.TagName)
		}

		findOptions.SetSort(bson.D{{
			Key:   key,
			Value: mongoDBSortOrder,
		}})
	}

	return findOptions
}

// iterator represents a MongoDB/DocumentDB implementation of the storage.Iterator interface.
type iterator struct {
	cursor      *mongo.Cursor
	coll        *mongo.Collection
	filter      interface{}
	timeout     time.Duration
	customQuery bool
}

// Next moves the pointer to the next entry in the iterator.
// Note that it must be called before accessing the first entry.
// It returns false if the iterator is exhausted - this is not considered an error.
func (i *iterator) Next() (bool, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	return i.cursor.Next(ctxWithTimeout), nil
}

// Key returns the key of the current entry.
func (i *iterator) Key() (string, error) {
	key, _, err := getKeyAndValueFromMongoDBResult(i.cursor)
	if err != nil {
		return "", fmt.Errorf("failed to get key from MongoDB result: %w", err)
	}

	return key, nil
}

// Value returns the value of the current entry.
func (i *iterator) Value() ([]byte, error) {
	_, value, err := getKeyAndValueFromMongoDBResult(i.cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from MongoDB result: %w", err)
	}

	return value, nil
}

// ValueAsRawMap returns the full MongoDB JSON document of the current entry.
// The document is returned as a map (which includes the _id field).
func (i *iterator) ValueAsRawMap() (map[string]interface{}, error) {
	return getValueAsRawMapFromMongoDBResult(i.cursor)
}

// Tags returns the tags associated with the key of the current entry.
// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
func (i *iterator) Tags() ([]storage.Tag, error) {
	tags, err := getTagsFromMongoDBResult(i.cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from MongoDB result: %w", err)
	}

	return tags, nil
}

// TODO (#147) Investigate using aggregates to get total items without doing a separate query.

// TotalItems returns a count of the number of entries (key + value + tags triplets) matched by the query
// that generated this iterator. This count is not affected by the page settings used (i.e. the count is of all
// results as if you queried starting from the first page and with an unlimited page size).
// Depending on the storage implementation, you may need to ensure that the TagName used in the query is in the
// Store's StoreConfiguration before trying to call this method (or it may be optional, but recommended).
// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
func (i *iterator) TotalItems() (int, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	totalItems, err := i.coll.CountDocuments(ctxWithTimeout, i.filter)
	if err != nil {
		return -1, fmt.Errorf("failed to get document count from MongoDB: %w", err)
	}

	return int(totalItems), nil
}

// Close closes this iterator object, freeing resources.
func (i *iterator) Close() error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	return i.cursor.Close(ctxWithTimeout)
}

func setOptions(opts []Option, p *Provider) {
	for _, opt := range opts {
		opt(p)
	}

	if p.logger == nil {
		p.logger = &defaultLogger{
			log.New(os.Stdout, "MongoDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
		}
	}

	if p.timeout == 0 {
		p.timeout = defaultTimeout
	}

	if p.maxRetries < 1 {
		p.maxRetries = defaultMaxIndexCreationConflictRetries
	}
}

func isIndexConflictErrorMessage(err error) bool {
	// DocumentDB may return either of these two error message.
	documentDBPossibleErrMsg1 := "Non-unique"
	documentDBPossibleErrMsg2 := "Existing index build in progress on the same collection. " +
		"Collection is limited to a single index build at a time."
	documentDBPossibleErrMsg3 := "EOF"
	// MongoDB 5.0.0 may return this error message.
	mongoDB500PossibleErrMsg := "incomplete read of message header"

	if strings.Contains(err.Error(), documentDBPossibleErrMsg1) ||
		strings.Contains(err.Error(), documentDBPossibleErrMsg2) ||
		strings.Contains(err.Error(), documentDBPossibleErrMsg3) ||
		strings.Contains(err.Error(), mongoDB500PossibleErrMsg) {
		return true
	}

	return false
}

func validatePutInput(key string, value []byte, tags []storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}

		if strings.Contains(tag.Name, "<") { // This also handles the <= case.
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, "<") { // This also handles the <= case.
			return fmt.Errorf(invalidTagValue, tag.Value)
		}

		if strings.Contains(tag.Name, ">") { // This also handles the >= case.
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ">") { // This also handles the >= case.
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	return nil
}

func convertTagSliceToMap(tagSlice []storage.Tag) (map[string]interface{}, error) {
	tagsMap := make(map[string]interface{})

	for _, tag := range tagSlice {
		_, exists := tagsMap[tag.Name]
		if exists {
			return nil, fmt.Errorf("tag name %s appears in more than one tag. A single key-value pair cannot "+
				"have multiple tags that share the same tag name", tag.Name)
		}

		tagsMap[tag.Name] = convertToIntIfPossible(tag.Value)
	}

	return tagsMap, nil
}

// If possible, converts value to an int and returns it.
// Otherwise, it returns value as a string, untouched.
func convertToIntIfPossible(value string) interface{} {
	valueAsInt, err := strconv.Atoi(value)
	if err != nil {
		return value
	}

	return valueAsInt
}

func convertTagMapToSlice(tagMap map[string]interface{}) []storage.Tag {
	tagsSlice := make([]storage.Tag, len(tagMap))

	var counter int

	for tagName, tagValue := range tagMap {
		tagsSlice[counter] = storage.Tag{
			Name:  tagName,
			Value: fmt.Sprintf("%v", tagValue),
		}

		counter++
	}

	return tagsSlice
}

type decoder interface {
	Decode(interface{}) error
}

func getKeyAndValueFromMongoDBResult(decoder decoder) (key string, value []byte, err error) {
	data, errGetDataWrapper := getDataWrapperFromMongoDBResult(decoder)
	if errGetDataWrapper != nil {
		return "", nil, fmt.Errorf("failed to get data wrapper from MongoDB result: %w", errGetDataWrapper)
	}

	if data.Doc != nil {
		unescapedMap := unescapeMapForDocumentDB(data.Doc)

		dataBytes, errMarshal := json.Marshal(unescapedMap)
		if errMarshal != nil {
			return "", nil, fmt.Errorf("failed to marshal value into bytes: %w", errMarshal)
		}

		return data.Key, dataBytes, nil
	}

	if data.Bin != nil {
		return data.Key, data.Bin, nil
	}

	valueBytes, err := json.Marshal(data.Str)
	if err != nil {
		return "", nil, fmt.Errorf("marshal string value: %w", err)
	}

	return data.Key, valueBytes, nil
}

func getKeyAndRawMapFromMongoDBResult(decoder decoder) (key string, doc map[string]interface{}, err error) {
	doc, errGetDataWrapper := getValueAsRawMapFromMongoDBResult(decoder)
	if errGetDataWrapper != nil {
		return "", nil, fmt.Errorf("failed to get data wrapper from MongoDB result: %w", errGetDataWrapper)
	}

	id, ok := doc["_id"]
	if !ok {
		return "", nil, fmt.Errorf("no _id field in document")
	}

	key, ok = id.(string)
	if !ok {
		return "", nil, fmt.Errorf("_id field in document is not a string")
	}

	return key, doc, nil
}

func getTagsFromMongoDBResult(decoder decoder) ([]storage.Tag, error) {
	data, err := getDataWrapperFromMongoDBResult(decoder)
	if err != nil {
		return nil, fmt.Errorf("failed to get data wrapper from MongoDB result: %w", err)
	}

	return convertTagMapToSlice(data.Tags), nil
}

// getDataWrapperFromMongoDBResult unmarshals and returns a dataWrapper from the MongoDB result.
func getDataWrapperFromMongoDBResult(decoder decoder) (*dataWrapper, error) {
	data := &dataWrapper{}

	if err := decoder.Decode(data); err != nil {
		return nil, fmt.Errorf("failed to decode data from MongoDB: %w", err)
	}

	return data, nil
}

func getValueAsRawMapFromMongoDBResult(decoder decoder) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	if err := decoder.Decode(data); err != nil {
		return nil, fmt.Errorf("failed to decode data from MongoDB: %w", err)
	}

	return data, nil
}

func getQueryOptions(options []storage.QueryOption) storage.QueryOptions {
	var queryOptions storage.QueryOptions

	for _, option := range options {
		if option != nil {
			option(&queryOptions)
		}
	}

	if queryOptions.InitialPageNum < 0 {
		queryOptions.InitialPageNum = 0
	}

	return queryOptions
}

// PrepareFilter converts the expression into a MongoDB filter.
func PrepareFilter(expressions []string, isJSONQuery bool) (bson.D, error) {
	operands := make(bson.D, len(expressions))

	for i, exp := range expressions {
		operand, err := prepareSingleOperand(exp, isJSONQuery)
		if err != nil {
			return nil, err
		}

		operands[i] = operand
	}

	// When the bson.D below gets serialized, it'll be comma separated.
	// MongoDB treats a comma separated list of expression as an implicit AND operation.
	return operands, nil
}

func prepareSingleOperand(expression string, isJSONQuery bool) (bson.E, error) {
	var filterValue interface{}

	operator, splitExpression, err := determineOperatorAndSplit(expression)
	if err != nil {
		return bson.E{}, err
	}

	var key string

	if isJSONQuery {
		key = splitExpression[0]
	} else {
		key = fmt.Sprintf("tags.%s", splitExpression[0])
	}

	if operator == "$lt" || operator == "$lte" || operator == "$gt" || operator == "$gte" {
		value, err := strconv.Atoi(splitExpression[1])
		if err != nil {
			return bson.E{}, fmt.Errorf("invalid query format. when using any one of the <=, <, >=, > "+
				"operators, the immediate value on the right side side must be a valid integer: %w", err)
		}

		filterValue = bson.D{
			{Key: operator, Value: value},
		}

		operand := bson.E{
			Key:   key,
			Value: filterValue,
		}

		return operand, nil
	}

	if operator == "$exists" {
		filterValue = bson.D{
			{Key: "$exists", Value: true},
		}
	} else {
		filterValue = convertToIntIfPossible(splitExpression[1])
	}

	operand := bson.E{
		Key:   key,
		Value: filterValue,
	}

	return operand, nil
}

// determineOperatorAndSplit takes the given expression and returns the operator (in the format required by MongoDB)
// along with the expression split by the operator (as defined in the Store.Query documentation).
func determineOperatorAndSplit(expression string) (mongoDBOperator string, expressionSplit []string, err error) {
	expressionSplitByLessThanOrEqualTo := strings.Split(expression, "<=")
	if len(expressionSplitByLessThanOrEqualTo) == lessThanGreaterThanExpressionLength {
		return "$lte", expressionSplitByLessThanOrEqualTo, nil
	}

	expressionSplitByLessThan := strings.Split(expression, "<")
	if len(expressionSplitByLessThan) == lessThanGreaterThanExpressionLength {
		return "$lt", expressionSplitByLessThan, nil
	}

	expressionSplitByGreaterThanOrEqualTo := strings.Split(expression, ">=")
	if len(expressionSplitByGreaterThanOrEqualTo) == lessThanGreaterThanExpressionLength {
		return "$gte", expressionSplitByGreaterThanOrEqualTo, nil
	}

	expressionSplitByGreaterThan := strings.Split(expression, ">")
	if len(expressionSplitByGreaterThan) == lessThanGreaterThanExpressionLength {
		return "$gt", expressionSplitByGreaterThan, nil
	}

	expressionSplitByEquals := strings.Split(expression, ":")
	switch len(expressionSplitByEquals) {
	case equalsExpressionTagNameOnlyLength:
		return "$exists", expressionSplitByEquals, nil
	case equalsExpressionTagNameAndValueLength:
		return "", expressionSplitByEquals, nil
	default:
		return "", nil, errInvalidQueryExpressionFormat
	}
}

func generateModelForBulkWriteCall(operation storage.Operation) (model mongo.WriteModel,
	isInsertOneModel bool, err error) {
	if operation.Value == nil {
		return mongo.NewDeleteOneModel().SetFilter(bson.M{"_id": operation.Key}), false, nil
	}

	data, err := generateDataWrapper(operation.Key, operation.Value, operation.Tags)
	if err != nil {
		return nil, false, err
	}

	if operation.PutOptions != nil && operation.PutOptions.IsNewKey {
		return mongo.NewInsertOneModel().SetDocument(data), true, nil
	}

	return mongo.NewReplaceOneModel().
		SetFilter(bson.M{"_id": operation.Key}).
		SetReplacement(data).
		SetUpsert(true), false, nil
}

func generateDataWrapper(key string, value []byte, tags []storage.Tag) (dataWrapper, error) {
	tagsAsMap, err := convertTagSliceToMap(tags)
	if err != nil {
		return dataWrapper{}, err
	}

	data := dataWrapper{
		Key:  key,
		Tags: tagsAsMap,
	}

	dataAsMap, err := convertMarshalledValueToMap(value)

	switch {
	case err == nil:
		data.Doc = dataAsMap
	case errors.Is(err, errUnmarshalBytesIntoMap):
		var unmarshalledStringValue string

		err = json.Unmarshal(value, &unmarshalledStringValue)
		if err == nil {
			data.Str = unmarshalledStringValue
		} else {
			data.Bin = value
		}
	default:
		return dataWrapper{}, err
	}

	return data, nil
}

// PrepareDataForBSONStorage takes the given value and converts it to the type expected by the MongoDB driver for
// inserting documents. The value must be a struct with exported fields and proper json tags or a map. To use the
// MongoDB primary key (_id), you must have an _id field in either the struct or map. Alternatively, add it to the
// map returned by this function. If no _id field is set, then MongoDB will generate one for you.
func PrepareDataForBSONStorage(value interface{}) (map[string]interface{}, error) {
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return convertMarshalledValueToMap(valueBytes)
}

func convertMarshalledValueToMap(valueBytes []byte) (map[string]interface{}, error) {
	var unmarshalledValue map[string]interface{}

	jsonDecoder := json.NewDecoder(bytes.NewReader(valueBytes))
	jsonDecoder.UseNumber()

	err := jsonDecoder.Decode(&unmarshalledValue)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errUnmarshalBytesIntoMap, err.Error())
	}

	escapedMap, err := escapeMapForDocumentDB(unmarshalledValue)
	if err != nil {
		return nil, err
	}

	return escapedMap, nil
}

// escapeMapForDocumentDB recursively travels through the given map and ensures that all keys are safe for DocumentDB.
// All "." characters in keys are replaced with "`" characters.
// If any "`" characters are discovered in keys then an error is returned, since this would cause confusion with the
// scheme described above.
func escapeMapForDocumentDB(unescapedMap map[string]interface{}) (map[string]interface{}, error) {
	escapedMap := make(map[string]interface{})

	for unescapedKey, unescapedValue := range unescapedMap {
		escapedKey, escapedValue, err := escapeKeyValuePair(unescapedKey, unescapedValue)
		if err != nil {
			return nil, err
		}

		escapedMap[escapedKey] = escapedValue
	}

	return escapedMap, nil
}

func escapeKeyValuePair(unescapedKey string, unescapedValue interface{}) (escapedKey string, escapedValue interface{},
	err error) {
	if strings.Contains(unescapedKey, "`") {
		return "", nil,
			fmt.Errorf(`JSON keys cannot have "`+"`"+`" characters within them. Invalid key: %s`, unescapedKey)
	}

	escapedValue, err = escapeValue(unescapedValue)
	if err != nil {
		return "", nil, err
	}

	return escapeKey(unescapedKey), escapedValue, nil
}

func escapeKey(unescapedKey string) string {
	return strings.ReplaceAll(unescapedKey, ".", "`")
}

func escapeValue(unescapedValue interface{}) (interface{}, error) {
	unescapedValueAsArray, ok := unescapedValue.([]interface{})
	if ok {
		return escapeArray(unescapedValueAsArray)
	}

	unescapedValueAsMap, ok := unescapedValue.(map[string]interface{})
	if ok {
		escapedValue, err := escapeMapForDocumentDB(unescapedValueAsMap)
		if err != nil {
			return nil, err
		}

		return escapedValue, nil
	}

	// In this case, the value is not a nested object or array and so doesn't need escaping.
	return unescapedValue, nil
}

func escapeArray(unescapedArray []interface{}) (interface{}, error) {
	escapedArray := make([]interface{}, len(unescapedArray))

	for i, unescapedValueInUnescapedArray := range unescapedArray {
		escapedValue, err := escapeValue(unescapedValueInUnescapedArray)
		if err != nil {
			return nil, err
		}

		escapedArray[i] = escapedValue
	}

	return escapedArray, nil
}

// This method is the inverse of the escapeMapForDocumentDB method.
func unescapeMapForDocumentDB(escapedMap map[string]interface{}) map[string]interface{} {
	unescapedMap := make(map[string]interface{})

	for escapedKey, escapedValue := range escapedMap {
		unescapedKey, unescapedValue := unescapeKeyValuePair(escapedKey, escapedValue)

		unescapedMap[unescapedKey] = unescapedValue
	}

	return unescapedMap
}

func unescapeKeyValuePair(escapedKey string, escapedValue interface{}) (key string, unescapedValue interface{}) {
	return unescapeKey(escapedKey), unescapeValue(escapedValue)
}

func unescapeKey(escapedKey string) string {
	return strings.ReplaceAll(escapedKey, "`", ".")
}

func unescapeValue(escapedValue interface{}) interface{} {
	escapedValueAsArray, ok := escapedValue.(bson.A)
	if ok {
		return unescapeArray(escapedValueAsArray)
	}

	escapedValueAsMap, ok := escapedValue.(map[string]interface{})
	if ok {
		return unescapeMapForDocumentDB(escapedValueAsMap)
	}

	// In this case, the value is not a nested object or array and so doesn't need unescaping.
	return escapedValue
}

func unescapeArray(escapedArray []interface{}) interface{} {
	unescapedArray := make([]interface{}, len(escapedArray))

	for i, escapedValueInEscapedArray := range escapedArray {
		unescapedArray[i] = unescapeValue(escapedValueInEscapedArray)
	}

	return unescapedArray
}
