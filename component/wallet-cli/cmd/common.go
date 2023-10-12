/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/piprate/json-gold/ld"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/ldutil"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/vdrutil"
)

type serviceFlags struct {
	levelDBPath             string
	mongoDBConnectionString string
	contextProviderURL      string
}

type services struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	cryptoSuite     api.Suite
}

func initServices(flags *serviceFlags, tlsConfig *tls.Config) (*services, error) {
	var (
		storageType string
		opts        []storage.Opt
	)

	if flags.levelDBPath != "" {
		storageType = "leveldb"
		opts = append(opts, storage.WithDBPath(flags.levelDBPath))
	} else if flags.mongoDBConnectionString != "" {
		storageType = "mongodb"
		opts = append(opts, storage.WithConnectionString(flags.mongoDBConnectionString))
	} else {
		return nil, fmt.Errorf("either --leveldb-path or --mongodb-connection-string must be specified")
	}

	slog.Info("initializing storage provider",
		"storage_type", storageType,
	)

	storageProvider, err := storage.NewProvider(storageType, opts...)
	if err != nil {
		return nil, err
	}

	var ldOpts []ldutil.Opt

	if flags.contextProviderURL != "" {
		ldOpts = append(ldOpts, ldutil.WithRemoteProviderURL(flags.contextProviderURL))
	}

	documentLoader, err := ldutil.DocumentLoader(storageProvider, ldOpts...)
	if err != nil {
		return nil, err
	}

	vdr, err := vdrutil.NewRegistry(tlsConfig)
	if err != nil {
		return nil, err
	}

	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, err
	}

	suite, err := localsuite.NewLocalCryptoSuite("local-lock://wallet-cli", kmsStore, &noop.NoLock{})
	if err != nil {
		return nil, err
	}

	return &services{
		storageProvider: storageProvider,
		documentLoader:  documentLoader,
		vdrRegistry:     vdr,
		cryptoSuite:     suite,
	}, nil
}

func (p *services) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *services) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *services) VDR() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *services) CryptoSuite() api.Suite {
	return p.cryptoSuite
}
