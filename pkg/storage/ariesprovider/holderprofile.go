/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider //nolint:dupl // Similar code but different types

import (
	"encoding/json"
	"fmt"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/vcs/pkg/storage"
)

const holderProfileStoreName = "holderprofiles"

type AriesHolderProfileStore struct {
	ariesStore ariesstorage.Store
}

func (a *AriesVCSProvider) OpenHolderProfileStore() (storage.HolderProfileStore, error) {
	ariesStore, err := a.provider.OpenStore(holderProfileStoreName)
	if err != nil {
		return nil, err
	}

	return &AriesHolderProfileStore{ariesStore: ariesStore}, nil
}

func (a *AriesHolderProfileStore) Put(profile storage.HolderProfile) error {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %w", err)
	}

	return a.ariesStore.Put(profile.Name, bytes)
}

func (a *AriesHolderProfileStore) Get(name string) (storage.HolderProfile, error) {
	holderProfileBytes, err := a.ariesStore.Get(name)
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

func (a *AriesHolderProfileStore) Delete(name string) error {
	return a.ariesStore.Delete(name)
}
