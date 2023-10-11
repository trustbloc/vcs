/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/legacy/mem"
	"github.com/trustbloc/kms-go/spi/storage"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage/leveldb"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage/mongodb"
)

func NewProvider(storageType string, opts ...Opt) (storage.Provider, error) {
	options := &providerOpts{}

	for _, opt := range opts {
		opt(options)
	}

	switch strings.ToLower(storageType) {
	case "mongodb":
		if options.connectionString == "" {
			return nil, fmt.Errorf("mongodb connection string is empty")
		}

		p, err := mongodb.NewProvider(options.connectionString)
		if err != nil {
			return nil, err
		}

		return p, nil
	case "leveldb":
		if options.dbPath == "" {
			return nil, fmt.Errorf("leveldb db path is empty")
		}

		return leveldb.NewProvider(options.dbPath), nil
	case "mem":
		return mem.NewProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

type providerOpts struct {
	connectionString string
	dbPath           string
}

type Opt func(opts *providerOpts)

func WithConnectionString(connectionString string) Opt {
	return func(opts *providerOpts) {
		opts.connectionString = connectionString
	}
}

func WithDBPath(dbPath string) Opt {
	return func(opts *providerOpts) {
		opts.dbPath = dbPath
	}
}
