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

const issuerProfileStoreName = "issuerprofiles"

type AriesIssuerProfileStore struct {
	ariesStore ariesstorage.Store
}

func (a *AriesVCSProvider) OpenIssuerProfileStore() (storage.IssuerProfileStore, error) {
	ariesStore, err := a.provider.OpenStore(issuerProfileStoreName)
	if err != nil {
		return nil, err
	}

	return &AriesIssuerProfileStore{ariesStore: ariesStore}, nil
}

func (i *AriesIssuerProfileStore) Put(profile storage.IssuerProfile) error {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %w", err)
	}

	return i.ariesStore.Put(profile.Name, bytes)
}

func (i *AriesIssuerProfileStore) Get(name string) (storage.IssuerProfile, error) {
	issuerProfileBytes, err := i.ariesStore.Get(name)
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

func (i *AriesIssuerProfileStore) Delete(name string) error {
	return i.ariesStore.Delete(name)
}
