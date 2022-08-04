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

const verifierProfileStoreName = "verifierprofiles"

type AriesVerifierProfileStore struct {
	ariesStore ariesstorage.Store
}

func (a *AriesVCSProvider) OpenVerifierProfileStore() (storage.VerifierProfileStore, error) {
	ariesStore, err := a.provider.OpenStore(verifierProfileStoreName)
	if err != nil {
		return nil, err
	}

	return &AriesVerifierProfileStore{ariesStore: ariesStore}, nil
}

func (v *AriesVerifierProfileStore) Put(profile storage.VerifierProfile) error {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %w", err)
	}

	return v.ariesStore.Put(profile.ID, bytes)
}

func (v *AriesVerifierProfileStore) Get(id string) (storage.VerifierProfile, error) {
	verifierProfileBytes, err := v.ariesStore.Get(id)
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

func (v *AriesVerifierProfileStore) Delete(id string) error {
	return v.ariesStore.Delete(id)
}
