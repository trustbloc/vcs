/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"github.com/trustbloc/kms-go/spi/storage"
)

// MockProvider is a mock edge storage provider that can hold several stores, not just one.
type MockProvider struct {
	Stores   map[string]storage.Store
	OpenErr  error
	CloseErr error
}

// OpenStore opens the store.
func (m *MockProvider) OpenStore(name string) (storage.Store, error) {
	if m.OpenErr != nil {
		return nil, m.OpenErr
	}

	s, exists := m.Stores[name]
	if !exists {
		return nil, storage.ErrStoreNotFound
	}

	return s, nil
}

// SetStoreConfig is not implemented.
func (m *MockProvider) SetStoreConfig(_ string, _ storage.StoreConfiguration) error {
	panic("implement me")
}

// GetStoreConfig is not implemented.
func (m *MockProvider) GetStoreConfig(_ string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

// GetOpenStores is not implemented.
func (m *MockProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

// Close all stores.
func (m *MockProvider) Close() error {
	return m.CloseErr
}
