/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"fmt"

	ldstoreapi "github.com/hyperledger/aries-framework-go/component/models/ld/store"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/ldstore"
)

// StoreProvider provides stores for JSON-LD contexts and remote providers.
type StoreProvider struct {
	ContextStore        ldstoreapi.ContextStore
	RemoteProviderStore ldstoreapi.RemoteProviderStore
	CacheImpl           Cache
}

// NewStoreProvider returns a new instance of StoreProvider.
func NewStoreProvider(mongoClient *mongodb.Client, cacheImpl Cache) (*StoreProvider, error) {
	contextStore, err := ldstore.NewContextStore(mongoClient)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mongoClient)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &StoreProvider{
		ContextStore:        NewCachedContextStore(cacheImpl, contextStore),
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

// JSONLDContextStore returns JSON-LD context store.
func (p *StoreProvider) JSONLDContextStore() ldstoreapi.ContextStore {
	return p.ContextStore
}

// JSONLDRemoteProviderStore returns JSON-LD remote provider store.
func (p *StoreProvider) JSONLDRemoteProviderStore() ldstoreapi.RemoteProviderStore {
	return p.RemoteProviderStore
}
