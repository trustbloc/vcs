/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"

	"github.com/henvic/httpretty"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

const (
	vdrResolveMaxRetry = 10
)

type Service struct {
	ariesServices  *ariesServices
	wallet         *wallet.Wallet
	vcProvider     vcprovider.VCProvider
	vcProviderConf *vcprovider.Config
	httpClient     *http.Client
	oauthClient    *oauth2.Config
	token          *oauth2.Token
	perfInfo       *PerfInfo
	debug          bool
}

func New(vcProviderType string, opts ...vcprovider.ConfigOption) (*Service, error) {
	vcProvider, err := vcprovider.GetProvider(vcProviderType, opts...)
	if err != nil {
		return nil, fmt.Errorf("GetVCProvider err: %w", err)
	}

	config := vcProvider.GetConfig()

	cookie, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	httpClient := &http.Client{
		Jar: cookie,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureTls},
		},
	}

	if config.Debug {
		httpLogger := &httpretty.Logger{
			RequestHeader:   true,
			RequestBody:     true,
			ResponseHeader:  true,
			ResponseBody:    true,
			SkipSanitize:    true,
			Colors:          true,
			SkipRequestInfo: true,
			Formatters:      []httpretty.Formatter{&httpretty.JSONFormatter{}},
			MaxResponseBody: 102400,
		}

		httpClient.Transport = httpLogger.RoundTripper(httpClient.Transport)
	}

	return &Service{
		vcProvider:     vcProvider,
		vcProviderConf: config,
		httpClient:     httpClient,
		perfInfo:       &PerfInfo{},
		debug:          config.Debug,
	}, nil
}

func (s *Service) GetConfig() *vcprovider.Config {
	return s.vcProviderConf
}

type PerfInfo struct {
	CreateWallet               time.Duration `json:"vci_create_wallet"`
	GetIssuerOIDCConfig        time.Duration `json:"vci_get_issuer_oidc_config"`
	GetAccessToken             time.Duration `json:"vci_get_access_token"`
	GetCredential              time.Duration `json:"vci_get_credential"`
	FetchRequestObject         time.Duration `json:"vp_fetch_request_object"`
	VerifyAuthorizationRequest time.Duration `json:"vp_verify_authorization_request"`
	QueryCredentialFromWallet  time.Duration `json:"vp_query_credential_from_wallet"`
	CreateAuthorizedResponse   time.Duration `json:"vp_create_authorized_response"`
	SendAuthorizedResponse     time.Duration `json:"vp_send_authorized_response"`
}

func (s *Service) GetPerfInfo() *PerfInfo {
	return s.perfInfo
}

func (s *Service) createAgentServices(tlsConfig *tls.Config) (*ariesServices, error) {
	var storageProvider storage.Provider
	switch strings.ToLower(s.vcProviderConf.StorageProvider) {
	case "mongodb":
		p, err := mongodb.NewProvider(s.vcProviderConf.StorageProviderConnString)
		if err != nil {
			return nil, err
		}
		storageProvider = p
	case "leveldb":
		p := leveldb.NewProvider(s.vcProviderConf.StorageProviderConnString)
		storageProvider = p
	default:
		storageProvider = mem.NewProvider()
	}

	provider := &ariesServices{
		storageProvider: storageProvider,
	}

	ldStore, err := createLDStore(provider.storageProvider)
	if err != nil {
		return nil, err
	}

	loader, err := createJSONLDDocumentLoader(ldStore, tlsConfig,
		[]string{s.vcProviderConf.ContextProviderURL}, true)
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	provider.documentLoader = loader

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

	vrd, err := createVDR(s.vcProviderConf.UniResolverURL, tlsConfig)
	if err != nil {
		return nil, err
	}

	provider.vdrRegistry = vrd

	return provider, nil
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

func createJSONLDDocumentLoader(ldStore *ldStoreProvider, tlsConfig *tls.Config,
	providerURLs []string, contextEnableRemote bool) (jsonld.DocumentLoader, error) {
	var loaderOpts []ld.DocumentLoaderOpts

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, url := range providerURLs {
		if url == "" {
			continue
		}

		loaderOpts = append(loaderOpts,
			ld.WithRemoteProvider(
				remote.NewProvider(url, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	if contextEnableRemote {
		loaderOpts = append(loaderOpts,
			ld.WithRemoteDocumentLoader(jsonld.NewDefaultDocumentLoader(http.DefaultClient)))
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

func createVDR(universalResolver string, tlsConfig *tls.Config) (vdrapi.Registry, error) {
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

	longForm, err := longform.New()
	if err != nil {
		return nil, err
	}

	opts = append(opts,
		vdr.WithVDR(longForm),
		vdr.WithVDR(key.New()),
		vdr.WithVDR(
			&webVDR{
				http: &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: tlsConfig,
					},
				},
				VDR: web.New(),
			},
		),
	)

	return vdr.New(opts...), nil
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
	http *http.Client
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	docRes, err := w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
	if err != nil {
		return nil, fmt.Errorf("failed to read did web: %w", err)
	}

	return docRes, nil
}
