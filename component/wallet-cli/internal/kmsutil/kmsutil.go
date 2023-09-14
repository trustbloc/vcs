/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsutil

import (
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/kms/localkms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/secretlock"
	"github.com/trustbloc/kms-go/spi/storage"
)

func NewLocalKMS(storageProvider storage.Provider) (*localkms.LocalKMS, error) {
	store, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, err
	}

	provider := kmsProvider{
		store:             store,
		secretLockService: &noop.NoLock{},
	}

	localKMS, err := localkms.New("local-lock://wallet-cli", &provider)
	if err != nil {
		return nil, err
	}

	return localKMS, nil
}

type kmsProvider struct {
	store             kmsapi.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kmsapi.Store {
	return k.store
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
