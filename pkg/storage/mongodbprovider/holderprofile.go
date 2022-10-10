/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider //nolint:dupl // Similar code but different types

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage"
)

const holderProfileStoreName = "holderprofiles"

type MongoDBHolderProfileStore struct {
	store *mongodb.Store
}

func (m *MongoDBVCSProvider) OpenHolderProfileStore() (storage.HolderProfileStore, error) {
	ariesStore, err := m.provider.OpenStore(holderProfileStoreName)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBHolderProfileStore{store: mongoDBStore}, nil
}

func (m *MongoDBHolderProfileStore) Put(profile storage.HolderProfile) error {
	// Save space in the database by using the profile name as the MongoDB document _id field
	// and removing the profile name from the profile JSON.
	id := profile.Name
	profile.Name = ""

	return m.store.PutAsJSON(id, profile)
}

func (m *MongoDBHolderProfileStore) Get(name string) (storage.HolderProfile, error) {
	mongoDBDocument, err := m.store.GetAsRawMap(name)
	if err != nil {
		return storage.HolderProfile{}, err
	}

	// Restore the name that was used as the _id field.
	mongoDBDocument[nameFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]

	holderProfileBytes, err := json.Marshal(mongoDBDocument)
	if err != nil {
		return storage.HolderProfile{}, err
	}

	holderProfile := storage.HolderProfile{}

	err = json.Unmarshal(holderProfileBytes, &holderProfile)
	if err != nil {
		return storage.HolderProfile{}, err
	}

	return holderProfile, nil
}

func (m *MongoDBHolderProfileStore) Delete(name string) error {
	return m.store.Delete(name)
}
