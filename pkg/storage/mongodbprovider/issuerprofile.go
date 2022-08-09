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

const issuerProfileStoreName = "issuerprofiles"

type MongoDBIssuerProfileStore struct {
	store *mongodb.Store
}

func (m *MongoDBVCSProvider) OpenIssuerProfileStore() (storage.IssuerProfileStore, error) {
	ariesStore, err := m.provider.OpenStore(issuerProfileStoreName)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBIssuerProfileStore{store: mongoDBStore}, nil
}

func (m *MongoDBIssuerProfileStore) Put(profile storage.IssuerProfile) error {
	// Save space in the database by using the profile name as the MongoDB document _id field
	// and removing the profile name from the profile JSON.
	id := profile.Name
	profile.Name = "" // Save space in the database by removing redundant data

	return m.store.PutAsJSON(id, profile)
}

func (m *MongoDBIssuerProfileStore) Get(name string) (storage.IssuerProfile, error) {
	mongoDBDocument, err := m.store.GetAsRawMap(name)
	if err != nil {
		return storage.IssuerProfile{}, err
	}

	// Restore the name that was used as the _id field.
	mongoDBDocument[nameFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]

	issuerProfileBytes, err := json.Marshal(mongoDBDocument)
	if err != nil {
		return storage.IssuerProfile{}, err
	}

	issuerProfile := storage.IssuerProfile{}

	err = json.Unmarshal(issuerProfileBytes, &issuerProfile)
	if err != nil {
		return storage.IssuerProfile{}, err
	}

	return issuerProfile, nil
}

func (m *MongoDBIssuerProfileStore) Delete(name string) error {
	return m.store.Delete(name)
}
