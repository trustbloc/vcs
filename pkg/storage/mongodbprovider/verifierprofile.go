/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider //nolint:dupl // Similar code but different types

import (
	"encoding/json"
	"errors"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage"
)

const (
	verifierProfileStoreName = "verifierprofiles"
)

type MongoDBVerifierProfileStore struct {
	store *mongodb.Store
}

func (m *MongoDBVCSProvider) OpenVerifierProfileStore() (storage.VerifierProfileStore, error) {
	ariesStore, err := m.provider.OpenStore(verifierProfileStoreName)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBVerifierProfileStore{store: mongoDBStore}, nil
}

func (m *MongoDBVerifierProfileStore) Put(profile storage.VerifierProfile) error {
	// Save space in the database by using the verifier profile ID as the MongoDB document _id field.
	// and removing the profile ID from the profile JSON.
	id := profile.ID
	profile.ID = ""

	return m.store.PutAsJSON(id, profile)
}

func (m *MongoDBVerifierProfileStore) Get(id string) (storage.VerifierProfile, error) {
	mongoDBDocument, err := m.store.GetAsRawMap(id)
	if err != nil {
		return storage.VerifierProfile{}, err
	}

	// Restore the verifier profile ID that was used as the _id field.
	mongoDBDocument[idFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]

	verifierProfileBytes, err := json.Marshal(mongoDBDocument)
	if err != nil {
		return storage.VerifierProfile{}, err
	}

	verifierProfile := storage.VerifierProfile{}

	err = json.Unmarshal(verifierProfileBytes, &verifierProfile)
	if err != nil {
		return storage.VerifierProfile{}, err
	}

	return verifierProfile, nil
}

func (m *MongoDBVerifierProfileStore) Delete(id string) error {
	return m.store.Delete(id)
}
