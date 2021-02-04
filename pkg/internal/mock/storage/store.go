/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

// MockProvider is a mock edge storage provider that can hold several stores, not just one.
type MockProvider struct {
	Stores        map[string]storage.Store
	CreateErr     error
	OpenErr       error
	CloseStoreErr error
	CloseErr      error
	CreateErrors  map[string]error
}

// CreateStore creates a store.
func (m *MockProvider) CreateStore(name string) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}

	if err, exists := m.CreateErrors[name]; exists {
		return err
	}

	if _, exists := m.Stores[name]; exists {
		return storage.ErrDuplicateStore
	}

	m.Stores[name] = &mockstore.MockStore{Store: make(map[string][]byte)}

	return nil
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

// CloseStore closes the store.
func (m *MockProvider) CloseStore(_ string) error {
	return m.CloseStoreErr
}

// Close all stores.
func (m *MockProvider) Close() error {
	return m.CloseErr
}
