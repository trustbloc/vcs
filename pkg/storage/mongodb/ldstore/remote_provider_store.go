/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldstore

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	remoteProviderCollectionName = "ldremoteprovider"
	idFieldName                  = "id"
	endpointFieldName            = "endpoint"
)

var _ ld.RemoteProviderStore = (*RemoteProviderStore)(nil)

// RemoteProviderStore is mongodb implementation of remote provider repository.
type RemoteProviderStore struct {
	mongoClient *mongodb.Client
}

// NewRemoteProviderStore returns a new instance of RemoteProviderStoreImpl.
func NewRemoteProviderStore(mongoClient *mongodb.Client) (*RemoteProviderStore, error) {
	s := &RemoteProviderStore{
		mongoClient: mongoClient,
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

func (s *RemoteProviderStore) migrate() error {
	collection := s.mongoClient.Database().Collection(remoteProviderCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	if _, err := collection.Indexes().
		CreateMany(ctxWithTimeout,
			[]mongo.IndexModel{
				{
					Keys: bson.D{
						{
							Key:   idFieldName,
							Value: 1,
						},
					},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{
						{
							Key:   endpointFieldName,
							Value: 1,
						},
					},
					Options: options.Index().SetUnique(true),
				},
			},
		); err != nil {
		return fmt.Errorf("create indexes: %w", err)
	}

	return nil
}

// Get returns a remote provider record from DB.
func (s *RemoteProviderStore) Get(id string) (*ld.RemoteProviderRecord, error) {
	collection := s.mongoClient.Database().Collection(remoteProviderCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	var provider ld.RemoteProviderRecord

	if err := collection.FindOne(ctxWithTimeout,
		bson.D{
			{
				Key:   idFieldName,
				Value: id,
			},
		},
	).Decode(&provider); err != nil {
		return nil, fmt.Errorf("find provider: %w", err)
	}

	return &provider, nil
}

// GetAll returns all remote provider records from DB.
func (s *RemoteProviderStore) GetAll() ([]ld.RemoteProviderRecord, error) {
	collection := s.mongoClient.Database().Collection(remoteProviderCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	cursor, err := collection.Find(ctxWithTimeout, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("find providers: %w", err)
	}

	defer cursor.Close(ctxWithTimeout) //nolint:errcheck

	var providers []ld.RemoteProviderRecord

	if err = cursor.All(ctxWithTimeout, &providers); err != nil {
		return nil, fmt.Errorf("get all providers: %w", err)
	}

	return providers, nil
}

// Save creates a new remote provider record and saves it into DB.
// If record with given endpoint already exists, it is returned to the caller.
func (s *RemoteProviderStore) Save(endpoint string) (*ld.RemoteProviderRecord, error) {
	var (
		provider ld.RemoteProviderRecord
		err      error
	)

	collection := s.mongoClient.Database().Collection(remoteProviderCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	if err = collection.FindOne(ctxWithTimeout,
		bson.D{
			{
				Key:   endpointFieldName,
				Value: endpoint,
			},
		},
	).Decode(&provider); err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("find provider: %w", err)
	}

	if err == nil {
		return &provider, nil
	}

	provider = ld.RemoteProviderRecord{
		ID:       uuid.New().String(),
		Endpoint: endpoint,
	}

	if _, err = collection.InsertOne(ctxWithTimeout, provider); err != nil {
		return nil, fmt.Errorf("save new remote provider record: %w", err)
	}

	return &provider, nil
}

// Delete deletes a remote provider record in DB.
func (s *RemoteProviderStore) Delete(id string) error {
	collection := s.mongoClient.Database().Collection(remoteProviderCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	if _, err := collection.DeleteOne(ctxWithTimeout,
		bson.D{
			{
				Key:   idFieldName,
				Value: id,
			},
		},
	); err != nil {
		return fmt.Errorf("delete remote provider record: %w", err)
	}

	return nil
}
