/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storewrapper

import (
	oldapi "github.com/hyperledger/aries-framework-go/spi/storage"
	newapi "github.com/trustbloc/kms-go/spi/storage"
)

// WrapProvider wraps a store provider from afgo APIs to be compatible with trustbloc ABIs.
func WrapProvider(prov oldapi.Provider) newapi.Provider {
	return &storeProviderWrapper{provider: prov}
}

type storeProviderWrapper struct {
	provider oldapi.Provider
}

type storeWrapper struct {
	store oldapi.Store
}

func (s *storeProviderWrapper) OpenStore(name string) (newapi.Store, error) {
	store, err := s.provider.OpenStore(name)
	if err != nil {
		return nil, err
	}

	return &storeWrapper{store: store}, nil
}

func (s *storeProviderWrapper) SetStoreConfig(name string, config newapi.StoreConfiguration) error {
	return s.provider.SetStoreConfig(name, oldapi.StoreConfiguration{TagNames: config.TagNames})
}

func (s *storeProviderWrapper) GetStoreConfig(name string) (newapi.StoreConfiguration, error) {
	conf, err := s.provider.GetStoreConfig(name)
	if err != nil {
		return newapi.StoreConfiguration{}, err
	}

	return newapi.StoreConfiguration{TagNames: conf.TagNames}, nil
}

func (s *storeProviderWrapper) GetOpenStores() []newapi.Store {
	stores := s.provider.GetOpenStores()

	out := make([]newapi.Store, len(stores))

	for i, store := range stores {
		out[i] = &storeWrapper{store: store}
	}

	return out
}

func (s *storeProviderWrapper) Close() error {
	return s.provider.Close()
}

func tagsToOld(tags []newapi.Tag) []oldapi.Tag {
	if tags == nil {
		return nil
	}

	oldTags := make([]oldapi.Tag, len(tags))

	for i, tag := range tags {
		oldTags[i] = oldapi.Tag{
			Name:  tag.Name,
			Value: tag.Value,
		}
	}

	return oldTags
}

func tagsToNew(tags []oldapi.Tag) []newapi.Tag {
	if tags == nil {
		return nil
	}

	newTags := make([]newapi.Tag, len(tags))

	for i, tag := range tags {
		newTags[i] = newapi.Tag{
			Name:  tag.Name,
			Value: tag.Value,
		}
	}

	return newTags
}

func (s *storeWrapper) Put(key string, value []byte, tags ...newapi.Tag) error {
	oldTags := tagsToOld(tags)

	return s.store.Put(key, value, oldTags...)
}

func (s *storeWrapper) Get(key string) ([]byte, error) {
	return s.store.Get(key)
}

func (s *storeWrapper) GetTags(key string) ([]newapi.Tag, error) {
	tags, err := s.store.GetTags(key)
	if err != nil {
		return nil, err
	}

	newTags := tagsToNew(tags)

	return newTags, nil
}

func (s *storeWrapper) GetBulk(keys ...string) ([][]byte, error) {
	return s.store.GetBulk(keys...)
}

func (s *storeWrapper) Query(expression string, options ...newapi.QueryOption) (newapi.Iterator, error) {
	srcOpts := &newapi.QueryOptions{}

	for _, option := range options {
		option(srcOpts)
	}

	oldOptions := []oldapi.QueryOption{
		func(opts *oldapi.QueryOptions) {
			if srcOpts.SortOptions != nil {
				opts.SortOptions = &oldapi.SortOptions{
					Order:   oldapi.SortOrder(srcOpts.SortOptions.Order),
					TagName: srcOpts.SortOptions.TagName,
				}
			}

			opts.PageSize = srcOpts.PageSize
			opts.InitialPageNum = srcOpts.InitialPageNum
		},
	}

	it, err := s.store.Query(expression, oldOptions...)
	if err != nil {
		return nil, err
	}

	return &iteratorWrapper{it: it}, nil
}

func (s *storeWrapper) Delete(key string) error {
	return s.store.Delete(key)
}

func (s *storeWrapper) Batch(operations []newapi.Operation) error {
	ops := make([]oldapi.Operation, len(operations))

	for i, operation := range operations {
		var putOpts *oldapi.PutOptions

		if operation.PutOptions != nil {
			putOpts = &oldapi.PutOptions{
				IsNewKey: operation.PutOptions.IsNewKey,
			}
		}

		ops[i] = oldapi.Operation{
			Key:        operation.Key,
			Value:      operation.Value,
			Tags:       tagsToOld(operation.Tags),
			PutOptions: putOpts,
		}
	}

	return s.store.Batch(ops)
}

func (s *storeWrapper) Flush() error {
	return s.store.Flush()
}

func (s *storeWrapper) Close() error {
	return s.store.Close()
}

type iteratorWrapper struct {
	it oldapi.Iterator
}

func (i *iteratorWrapper) Next() (bool, error) {
	return i.it.Next()
}

func (i *iteratorWrapper) Key() (string, error) {
	return i.it.Key()
}

func (i *iteratorWrapper) Value() ([]byte, error) {
	return i.it.Value()
}

func (i *iteratorWrapper) Tags() ([]newapi.Tag, error) {
	tags, err := i.it.Tags()
	if err != nil {
		return nil, err
	}

	return tagsToNew(tags), nil
}

func (i *iteratorWrapper) TotalItems() (int, error) {
	return i.it.TotalItems()
}

func (i *iteratorWrapper) Close() error {
	return i.it.Close()
}

var _ newapi.Provider = &storeProviderWrapper{}
var _ newapi.Store = &storeWrapper{}
var _ newapi.Iterator = &iteratorWrapper{}
