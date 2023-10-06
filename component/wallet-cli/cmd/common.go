/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"crypto/tls"
	"fmt"

	"github.com/piprate/json-gold/ld"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	storageapi "github.com/trustbloc/kms-go/spi/storage"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/kmsutil"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/ldutil"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/vdrutil"
)

type serviceFlags struct {
	storageType             string
	mongoDBConnectionString string
	levelDBPath             string
	contextProviderURL      string
}

type services struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	kms             kmsapi.KeyManager
}

func initServices(flags *serviceFlags, tlsConfig *tls.Config) (*services, error) {
	var storageOpts []storage.Opt

	switch flags.storageType {
	case "mem":
		break
	case "leveldb":
		if flags.levelDBPath == "" {
			return nil, fmt.Errorf("--leveldb-path is required when storage type is leveldb")
		}

		storageOpts = append(storageOpts, storage.WithDBPath(flags.levelDBPath))
	case "mongodb":
		if flags.mongoDBConnectionString == "" {
			return nil, fmt.Errorf("--mongodb-connection-string is required when storage type is mongodb")
		}

		storageOpts = append(storageOpts, storage.WithConnectionString(flags.mongoDBConnectionString))
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", flags.storageType)
	}

	storageProvider, err := storage.NewProvider(flags.storageType, storageOpts...)
	if err != nil {
		return nil, err
	}

	var opts []ldutil.Opt

	if flags.contextProviderURL != "" {
		opts = append(opts, ldutil.WithRemoteProviderURL(flags.contextProviderURL))
	}

	documentLoader, err := ldutil.DocumentLoader(storageProvider, opts...)
	if err != nil {
		return nil, err
	}

	vdr, err := vdrutil.NewRegistry(tlsConfig)
	if err != nil {
		return nil, err
	}

	localKMS, err := kmsutil.NewLocalKMS(storageProvider)
	if err != nil {
		return nil, err
	}

	return &services{
		storageProvider: storageProvider,
		documentLoader:  documentLoader,
		vdrRegistry:     vdr,
		kms:             localKMS,
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

func (p *services) KMS() kmsapi.KeyManager {
	return p.kms
}
