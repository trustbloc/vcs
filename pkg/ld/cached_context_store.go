/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package ld_test . Cache,ContextStore

package ld

import (
	jsonld "github.com/piprate/json-gold/ld"
	ldcontext "github.com/trustbloc/vc-go/ld/context"
	ldstore "github.com/trustbloc/vc-go/ld/store"
)

const (
	cacheItemCost = 1
)

// Cache represents caching functionality. Concrete implementation is expected to be thread-safe.
type Cache interface {
	Get(key interface{}) (interface{}, bool)
	Set(key, value interface{}, cost int64) bool
	Del(key interface{})
}

type ContextStore = ldstore.ContextStore

// CachedContextStore is a cached store for JSON-LD contexts.
type CachedContextStore struct {
	cache        Cache
	contextStore ContextStore
}

func NewCachedContextStore(cacheImpl Cache, contextStore ContextStore) *CachedContextStore {
	return &CachedContextStore{
		cache:        cacheImpl,
		contextStore: contextStore,
	}
}

func (s *CachedContextStore) Get(u string) (*jsonld.RemoteDocument, error) {
	if doc, ok := s.cache.Get(u); ok {
		return doc.(*jsonld.RemoteDocument), nil
	}

	doc, err := s.contextStore.Get(u)
	if err != nil {
		return nil, err
	}

	s.cache.Set(u, doc, cacheItemCost)

	return doc, nil
}

func (s *CachedContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	if err := s.contextStore.Put(u, rd); err != nil {
		return err
	}

	s.cache.Set(u, rd, cacheItemCost)

	return nil
}

func (s *CachedContextStore) Import(documents []ldcontext.Document) error {
	return s.contextStore.Import(documents)
}

func (s *CachedContextStore) Delete(documents []ldcontext.Document) error {
	for _, doc := range documents {
		s.cache.Del(doc.URL)
	}

	return s.contextStore.Delete(documents)
}
