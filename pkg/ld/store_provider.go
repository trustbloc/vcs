/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/store/ld"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/ldstore"
)

// StoreProvider provides stores for JSON-LD contexts and remote providers.
type StoreProvider struct {
	ContextStore        ld.ContextStore
	RemoteProviderStore ld.RemoteProviderStore
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
func (p *StoreProvider) JSONLDContextStore() ld.ContextStore {
	return p.ContextStore
}

// JSONLDRemoteProviderStore returns JSON-LD remote provider store.
func (p *StoreProvider) JSONLDRemoteProviderStore() ld.RemoteProviderStore {
	return p.RemoteProviderStore
}
