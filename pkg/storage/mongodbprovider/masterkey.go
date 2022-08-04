/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider

import (
	"errors"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage"
)

const (
	masterKeyStoreName = "masterkey"
	idName             = holderProfileStoreName
)

func (m *MongoDBVCSProvider) OpenMasterKeyStore() (storage.MasterKeyStore, error) {
	ariesStore, err := m.provider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBMasterKeyStore{store: mongoDBStore}, nil
}

type MongoDBMasterKeyStore struct {
	store *mongodb.Store
}

func (m *MongoDBMasterKeyStore) Put(masterKey []byte) error {
	return m.store.Put(idName, masterKey)
}

func (m *MongoDBMasterKeyStore) Get() ([]byte, error) {
	return m.store.Get(idName)
}
