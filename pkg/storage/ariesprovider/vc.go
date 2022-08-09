/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	storeName = "verifiablecredentials"
)

type AriesVCStore struct {
	ariesProvider ariesstorage.Provider
	ariesStore    ariesstorage.Store
}

func (a *AriesVCSProvider) OpenVCStore() (storage.VCStore, error) {
	ariesStore, err := a.provider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &AriesVCStore{ariesProvider: a.provider, ariesStore: ariesStore}, nil
}

func (v *AriesVCStore) Put(profileName string, vc *verifiable.Credential) error {
	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return err
	}

	return v.ariesStore.Put(generateVCEntryKey(profileName, vc.ID), vcBytes)
}

func (v *AriesVCStore) Get(profileName, vcID string) ([]byte, error) {
	return v.ariesStore.Get(generateVCEntryKey(profileName, vcID))
}

func generateVCEntryKey(profileName, credentialID string) string {
	return fmt.Sprintf("%s-%s", profileName, credentialID)
}
