/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package stress

import (
	"fmt"
	"net/http"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	ldstore "github.com/trustbloc/did-go/doc/ld/store"
	"github.com/trustbloc/did-go/method/web"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
)

type walletProvider struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdRegistry      vdrapi.Registry
	keyCreator      api.RawKeyCreator
}

func (p *walletProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *walletProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *walletProvider) VDRegistry() vdrapi.Registry {
	return p.vdRegistry
}

func (p *walletProvider) KeyCreator() api.RawKeyCreator {
	return p.keyCreator
}

type oidc4vciProvider struct {
	storageProvider  storageapi.Provider
	httpClient       *http.Client
	documentLoader   ld.DocumentLoader
	vdrRegistry      vdrapi.Registry
	cryptoSuite      api.Suite
	wallet           *wallet.Wallet
	wellKnownService *wellknown.Service
}

func (p *oidc4vciProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vciProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vciProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vciProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vciProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vciProvider) Wallet() *wallet.Wallet {
	return p.wallet
}

func (p *oidc4vciProvider) WellKnownService() *wellknown.Service {
	return p.wellKnownService
}

type oidc4vpProvider struct {
	storageProvider storageapi.Provider
	httpClient      *http.Client
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	cryptoSuite     api.Suite
	wallet          *wallet.Wallet
}

func (p *oidc4vpProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vpProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vpProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vpProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vpProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vpProvider) Wallet() *wallet.Wallet {
	return p.wallet
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

type webVDR struct {
	httpClient *http.Client
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	docRes, err := w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.httpClient))...)
	if err != nil {
		return nil, fmt.Errorf("read did web: %w", err)
	}

	return docRes, nil
}
