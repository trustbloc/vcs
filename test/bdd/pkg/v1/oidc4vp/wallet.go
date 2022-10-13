/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil/vdrutil"
)

const (
	didMethodVeres      = "v1"
	didMethodElement    = "elem"
	didMethodSov        = "sov"
	didMethodWeb        = "web"
	didMethodFactom     = "factom"
	didMethodORB        = "orb"
	didMethodKey        = "key"
	universalResolver   = "http://did-resolver.trustbloc.local:8072/1.0/identifiers"
	contextProviderURL  = "https://file-server.trustbloc.local:10096/ld-contexts.json"
	didDomain           = "https://testnet.orb.local"
	didServiceAuthToken = "tk1"
)

type ariesServices struct {
	storageProvider      storage.Provider
	vdrRegistry          vdrapi.Registry
	crypto               crypto.Crypto
	kms                  kms.KeyManager
	jSONLDDocumentLoader jsonld.DocumentLoader
	mediaTypeProfiles    []string
}

func (e *Steps) createWallet() error {
	e.walletUserID = "testUserID" + uuid.NewString()
	e.walletPassphrase = "passphrase122334"

	services, err := CreateAgentServices(e.tlsConfig)
	if err != nil {
		return fmt.Errorf("wallet services setup failed: %w", err)
	}

	e.ariesServices = services

	w, err := NewWallet(e.walletUserID, e.walletPassphrase, e.ariesServices)
	if err != nil {
		return err
	}
	e.wallet = w

	token, err := e.wallet.Open(wallet.WithUnlockByPassphrase(e.walletPassphrase))
	if err != nil {
		return fmt.Errorf("wallet unlock failed: %w", err)
	}

	e.walletToken = token

	vdr, err := orb.New(nil, orb.WithDomain(didDomain), orb.WithTLSConfig(e.tlsConfig),
		orb.WithAuthToken(didServiceAuthToken))
	if err != nil {
		return err
	}

	createRes, err := vdrutil.CreateDID(kms.ECDSAP384TypeDER, vdrpkg.New(vdrpkg.WithVDR(vdr), vdrpkg.WithVDR(key.New())), e.ariesServices.kms)
	if err != nil {
		return err
	}

	e.walletDidID = createRes.DidID
	e.walletDidKeyID = createRes.KeyID

	return nil
}

func (e *Steps) saveCredentialsInWallet() error {
	for _, cred := range e.bddContext.CreatedCredentialsSet {
		err := e.wallet.Add(e.walletToken, wallet.Credential, cred)
		if err != nil {
			return fmt.Errorf("wallet add credential failed: %w", err)
		}
	}

	return nil
}

func NewWallet(userID string, passphrase string, services *ariesServices) (*wallet.Wallet, error) {
	err := wallet.CreateProfile(userID, services, wallet.WithPassphrase(passphrase))
	if err != nil {
		return nil, fmt.Errorf("user profile create failed: %w", err)
	}

	w, err := wallet.New(userID, services)
	if err != nil {
		return nil, fmt.Errorf("create wallet failed: %w", err)
	}

	return w, nil

}

func (p *ariesServices) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p *ariesServices) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *ariesServices) Crypto() crypto.Crypto {
	return p.crypto
}

func (p *ariesServices) JSONLDDocumentLoader() jsonld.DocumentLoader {
	return p.jSONLDDocumentLoader
}

func (p *ariesServices) MediaTypeProfiles() []string {
	return p.mediaTypeProfiles
}

// Close frees resources being maintained by the framework.
func (p *ariesServices) Close() error {
	if p.storageProvider != nil {
		err := p.storageProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	if p.vdrRegistry != nil {
		if err := p.vdrRegistry.Close(); err != nil {
			return fmt.Errorf("vdr registry close failed: %w", err)
		}
	}

	return nil
}

func CreateAgentServices(tlsConfig *tls.Config) (*ariesServices, error) {
	provider := &ariesServices{}

	provider.storageProvider = mem.NewProvider()

	ldStore, err := createLDStore(provider.storageProvider)
	if err != nil {
		return nil, err
	}

	loader, err := createJSONLDDocumentLoader(ldStore, tlsConfig,
		[]string{contextProviderURL}, false)
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	provider.jSONLDDocumentLoader = loader

	cryptoImpl, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create local Crypto: %w", err)
	}

	provider.crypto = cryptoImpl

	kmsStore, err := kms.NewAriesProviderWrapper(provider.storageProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aries KMS store wrapper")
	}

	kmsProv := kmsProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	localKMS, err := localkms.New("local-lock://agentSDK", &kmsProv)
	if err != nil {
		return nil, fmt.Errorf("failed to create local KMS: %w", err)
	}
	provider.kms = localKMS

	vrd, err := createVDRI(universalResolver, tlsConfig)
	if err != nil {
		return nil, err
	}

	provider.vdrRegistry = vrd

	return provider, nil
}

func createJSONLDDocumentLoader(ldStore *ldStoreProvider, tlsConfig *tls.Config,
	providerURLs []string, contextEnableRemote bool) (jsonld.DocumentLoader, error) {
	var loaderOpts []ariesld.DocumentLoaderOpts

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, url := range providerURLs {
		loaderOpts = append(loaderOpts,
			ariesld.WithRemoteProvider(
				remote.NewProvider(url, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	if contextEnableRemote {
		loaderOpts = append(loaderOpts,
			ariesld.WithRemoteDocumentLoader(jsonld.NewDefaultDocumentLoader(http.DefaultClient)))
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, err
	}

	return loader, nil
}

func createVDRI(universalResolver string, tlsConfig *tls.Config) (vdrapi.Registry, error) {
	var opts []vdr.Option

	if universalResolver != "" {
		universalResolverVDRI, err := httpbinding.New(universalResolver,
			httpbinding.WithAccept(acceptsDID), httpbinding.WithHTTPClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}))
		if err != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdr: %w", err)
		}

		// add universal resolver vdr
		opts = append(opts, vdr.WithVDR(universalResolverVDRI))
	}

	// add bloc vdr
	opts = append(opts, vdr.WithVDR(key.New()), vdr.WithVDR(&webVDR{
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			}},
		VDR: web.New(),
	}))

	return vdr.New(opts...), nil
}

// acceptsDID returns if given did method is accepted by VC REST api
func acceptsDID(method string) bool {
	return method == didMethodVeres || method == didMethodElement || method == didMethodSov ||
		method == didMethodWeb || method == didMethodFactom || method == didMethodORB || method == didMethodKey
}

type webVDR struct {
	http *http.Client
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*ariesdid.DocResolution, error) {
	docRes, err := w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
	if err != nil {
		return nil, fmt.Errorf("failed to read did web: %w", err)
	}

	return docRes, nil
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

func createLDStore(storageProvider storage.Provider) (*ldStoreProvider, error) {
	contextStore, err := ldstore.NewContextStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

type kmsProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kms.Store {
	return k.store
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
