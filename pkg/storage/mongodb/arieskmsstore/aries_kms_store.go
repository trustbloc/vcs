/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package arieskmsstore

import (
	"errors"
	"fmt"

	arieskms "github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Store provides local KMS storage using mongodb.
type Store struct {
	client *mongodb.Client
}

const (
	ariesKMSStoreName = "aries_kms_store"
)

// NewStore initializes a Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{client: mongoClient}
}

type dataWrapper struct {
	ID  string `bson:"_id"`
	Bin []byte `bson:"bin,omitempty"`
}

// Put stores the given key under the given keysetID. Overwrites silently.
func (s *Store) Put(keysetID string, key []byte) error {
	coll := s.client.Database().Collection(ariesKMSStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	_, err := coll.UpdateByID(ctx, keysetID, &dataWrapper{
		ID:  keysetID,
		Bin: key,
	}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}

	return nil
}

// Get retrieves the key stored under the given keysetID. If no key is found,
// the returned error is expected to wrap ErrKeyNotFound. KMS implementations
// may check to see if the error wraps that error type for certain operations.
func (s *Store) Get(keysetID string) ([]byte, error) {
	coll := s.client.Database().Collection(ariesKMSStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	result := &dataWrapper{}

	err := coll.FindOne(ctx, bson.M{"_id": keysetID}).Decode(result)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("%w. Underlying error: %s",
			arieskms.ErrKeyNotFound, err.Error())
	}

	if err != nil {
		return nil, err
	}

	return result.Bin, nil
}

// Delete deletes the key stored under the given keysetID. A KeyManager will
// assume that attempting to delete a non-existent key will not return an error.
func (s *Store) Delete(keysetID string) error {
	coll := s.client.Database().Collection(ariesKMSStoreName)

	ctx, cancel := s.client.ContextWithTimeout()
	defer cancel()

	_, err := coll.DeleteOne(ctx, bson.M{"_id": keysetID})
	if err != nil {
		return fmt.Errorf("failed to run DeleteOne command in MongoDB: %w", err)
	}

	return nil
}
