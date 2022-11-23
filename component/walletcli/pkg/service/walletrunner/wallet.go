/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil/vdrutil"
)

const (
	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodWeb     = "web"
	didMethodFactom  = "factom"
	didMethodORB     = "orb"
	didMethodKey     = "key"
	didMethodION     = "ion"
)

func (s *Service) CreateWallet() error {
	s.vcProviderConf.WalletParams.UserID = "testUserID" + uuid.NewString()
	s.vcProviderConf.WalletParams.Passphrase = "passphrase122334"

	services, err := s.createAgentServices(s.vcProviderConf.TLS)
	if err != nil {
		return fmt.Errorf("wallet services setup failed: %w", err)
	}

	s.ariesServices = services

	w, err := newWallet(s.vcProviderConf.WalletParams.UserID, s.vcProviderConf.WalletParams.Passphrase, s.ariesServices)
	if err != nil {
		return err
	}
	s.wallet = w

	token, err := s.wallet.Open(wallet.WithUnlockByPassphrase(s.vcProviderConf.WalletParams.Passphrase))
	if err != nil {
		return fmt.Errorf("wallet unlock failed: %w", err)
	}

	s.vcProviderConf.WalletParams.Token = token

	vdrService, err := orb.New(nil,
		orb.WithDomain(s.vcProviderConf.DidDomain),
		orb.WithTLSConfig(s.vcProviderConf.TLS),
		orb.WithAuthToken(s.vcProviderConf.DidServiceAuthToken))
	if err != nil {
		return err
	}

	vdrRegistry := vdrpkg.New(vdrpkg.WithVDR(vdrService), vdrpkg.WithVDR(key.New()))

	createRes, err := vdrutil.CreateDID(kms.ECDSAP384TypeDER, vdrRegistry, s.ariesServices.kms)
	if err != nil {
		return err
	}

	s.vcProviderConf.WalletParams.DidID = createRes.DidID
	s.vcProviderConf.WalletParams.DidKeyID = createRes.KeyID

	for i := 1; i <= vdrResolveMaxRetry; i++ {
		_, err = vdrRegistry.Resolve(s.vcProviderConf.WalletParams.DidID)
		if err == nil {
			break
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}

func newWallet(userID string, passphrase string, services *AriesServices) (*wallet.Wallet, error) {
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

func (s *Service) SaveCredentialInWallet(vc []byte) error {
	err := s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, vc)
	if err != nil {
		return fmt.Errorf("wallet add credential failed: %w", err)
	}

	return nil
}

func (s *Service) createAgentServices(tlsConfig *tls.Config) (*AriesServices, error) {
	provider := &AriesServices{
		storageProvider: mem.NewProvider(),
	}

	ldStore, err := createLDStore(provider.storageProvider)
	if err != nil {
		return nil, err
	}

	loader, err := createJSONLDDocumentLoader(ldStore, tlsConfig,
		[]string{s.vcProviderConf.ContextProviderURL}, false)
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

	vrd, err := createVDRI(s.vcProviderConf.UniResolverURL, tlsConfig)
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

// acceptsDID returns if given did method is accepted by VC REST api
func acceptsDID(method string) bool {
	return method == didMethodVeres || method == didMethodElement || method == didMethodSov ||
		method == didMethodWeb || method == didMethodFactom || method == didMethodORB ||
		method == didMethodKey || method == didMethodION
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
