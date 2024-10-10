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
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
)

type walletFlags struct {
	levelDBPath             string
	mongoDBConnectionString string
	contextProviderURL      string
	walletDIDIndex          int
}

func initWallet(flags *walletFlags) (*wallet.Wallet, *services, error) {
	svc, err := initServices(
		flags.levelDBPath,
		flags.mongoDBConnectionString,
		flags.contextProviderURL,
	)
	if err != nil {
		return nil, nil, err
	}

	keyCreator, err := svc.CryptoSuite().RawKeyCreator()
	if err != nil {
		return nil, nil, err
	}

	w, err := wallet.New(
		&walletProvider{
			storageProvider: svc.StorageProvider(),
			documentLoader:  svc.DocumentLoader(),
			vdrRegistry:     svc.VDR(),
			keyCreator:      keyCreator,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	if len(w.DIDs()) == 0 {
		return nil, nil, fmt.Errorf("wallet not initialized, please run 'create' command")
	}

	if len(w.DIDs()) < flags.walletDIDIndex {
		return nil, nil, fmt.Errorf("--wallet-did-index is out of range")
	}

	if len(w.DIDs()) > 1 && flags.walletDIDIndex == -1 {
		var dids []any

		for i, did := range w.DIDs() {
			dids = append(dids, fmt.Sprintf("%d", i), did.ID)
		}

		slog.Warn("wallet supports multiple DIDs",
			slog.Group("did", dids...),
		)
	}

	return w, svc, nil
}

type services struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	cryptoSuite     api.Suite
	tlsConfig       *tls.Config
}

func initServices(
	levelDBPath,
	mongoDBConnectionString,
	contextProviderURL string,
) (*services, error) {
	var (
		storageType string
		opts        []storage.Opt
	)

	if levelDBPath != "" {
		storageType = "leveldb"
		opts = append(opts, storage.WithDBPath(levelDBPath))
	} else if mongoDBConnectionString != "" {
		storageType = "mongodb"
		opts = append(opts, storage.WithConnectionString(mongoDBConnectionString))
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

	if contextProviderURL != "" {
		ldOpts = append(ldOpts, ldutil.WithRemoteProviderURL(contextProviderURL))
	}

	ldOpts = append(ldOpts, ldutil.WithContextEnableRemote())

	documentLoader, err := ldutil.DocumentLoader(storageProvider, ldOpts...)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
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
		tlsConfig:       tlsConfig,
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

func (p *services) TLSConfig() *tls.Config {
	return p.tlsConfig
}
