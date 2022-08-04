/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider

import (
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/vcs/pkg/storage"
)

const (
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName
)

func (a *AriesVCSProvider) OpenMasterKeyStore() (storage.MasterKeyStore, error) {
	ariesStore, err := a.provider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	return &AriesMasterKeyStore{ariesStore: ariesStore}, nil
}

type AriesMasterKeyStore struct {
	ariesStore ariesstorage.Store
}

func (s *AriesMasterKeyStore) Put(masterKey []byte) error {
	return s.ariesStore.Put(masterKeyDBKeyName, masterKey)
}

func (s *AriesMasterKeyStore) Get() ([]byte, error) {
	return s.ariesStore.Get(masterKeyDBKeyName)
}
