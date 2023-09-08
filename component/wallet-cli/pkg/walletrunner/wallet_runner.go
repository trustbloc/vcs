/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/henvic/httpretty"
	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/legacy/mem"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/longform"
	"github.com/trustbloc/did-go/vdr"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/did-go/vdr/httpbinding"
	"github.com/trustbloc/did-go/vdr/key"
	"github.com/trustbloc/did-go/vdr/web"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/kms/localkms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/secretlock"
	"github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/vc-go/did"
	ldcontext "github.com/trustbloc/vc-go/ld/context"
	"github.com/trustbloc/vc-go/ld/context/remote"
	ld "github.com/trustbloc/vc-go/ld/documentloader"
	ldstore "github.com/trustbloc/vc-go/ld/store"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/storage/mongodb"
	"github.com/trustbloc/vcs/internal/storewrapper"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

// nolint:gochecknoglobals //embedded test contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocab []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
	//go:embed contexts/revocation-list-2021.jsonld
	revocationList2021 []byte
)

const (
	vdrResolveMaxRetry         = 10
	discoverableClientIDScheme = "urn:ietf:params:oauth:client-id-scheme:oauth-discoverable-client"
)

var extraContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld", // resolvable
		Content:     citizenshipVocab,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: examplesVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		Content: examplesExtVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-crude-product-v1.jsonld",
		Content: examplesCrudeProductVocab,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
	{
		URL:         "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld",
		DocumentURL: "https://raw.githubusercontent.com/w3c-ccg/vc-status-list-2021/343b8b59cddba4525e1ef355356ae760fc75904e/contexts/v1.jsonld",
		Content:     revocationList2021,
	},
}

type Service struct {
	ariesServices  *ariesServices
	wallet         Wallet
	vcProvider     vcprovider.VCProvider
	vcProviderConf *vcprovider.Config
	httpClient     *http.Client
	oauthClient    *oauth2.Config
	token          *oauth2.Token
	perfInfo       *PerfInfo
	vpFlowExecutor *VPFlowExecutor
	keepWalletOpen bool
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
			TLSClientConfig: config.TLS,
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
		keepWalletOpen: config.KeepWalletOpen,
	}, nil
}

func (s *Service) GetConfig() *vcprovider.Config {
	return s.vcProviderConf
}

type PerfInfo struct {
	CreateWallet                   time.Duration `json:"vci_create_wallet"`
	GetIssuerOIDCConfig            time.Duration `json:"vci_get_issuer_oidc_config"`
	GetIssuerCredentialsOIDCConfig time.Duration `json:"vci_get_issuer_credentials_oidc_config"`
	GetAccessToken                 time.Duration `json:"vci_get_access_token"`
	GetCredential                  time.Duration `json:"vci_get_credential"`
	FetchRequestObject             time.Duration `json:"vp_fetch_request_object"`
	VerifyAuthorizationRequest     time.Duration `json:"vp_verify_authorization_request"`
	QueryCredentialFromWallet      time.Duration `json:"vp_query_credential_from_wallet"`
	CreateAuthorizedResponse       time.Duration `json:"vp_create_authorized_response"`
	SendAuthorizedResponse         time.Duration `json:"vp_send_authorized_response"`
	VcsCIFlowDuration              time.Duration `json:"_vcs_ci_flow_duration"`
	VcsVPFlowDuration              time.Duration `json:"_vcs_vp_flow_duration"`
}

func (s *Service) GetPerfInfo() *PerfInfo {
	return s.perfInfo
}

func (s *Service) createAgentServices(vcProviderConf *vcprovider.Config) (*ariesServices, error) {
	var storageProvider storage.Provider
	switch strings.ToLower(s.vcProviderConf.StorageProvider) {
	case "mongodb":
		p, err := mongodb.NewProvider(s.vcProviderConf.StorageProviderConnString, nil)
		if err != nil {
			return nil, err
		}
		storageProvider = p
	case "leveldb":
		p := leveldb.NewProvider(s.vcProviderConf.StorageProviderConnString)
		storageProvider = storewrapper.WrapProvider(p)
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

	loader, err := createJSONLDDocumentLoader(ldStore, vcProviderConf.TLS,
		[]string{s.vcProviderConf.ContextProviderURL}, true)
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	provider.documentLoader = loader

	cryptoImpl, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create local DataProtector: %w", err)
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

	vrd, err := createVDR(vcProviderConf)
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
	loaderOpts := []ld.Opts{ld.WithExtraContexts(extraContexts...)}

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

func createVDR(vcProviderConf *vcprovider.Config) (vdrapi.Registry, error) {
	var opts []vdr.Option

	if vcProviderConf.UniResolverURL != "" {
		universalResolverVDRI, err := httpbinding.New(vcProviderConf.UniResolverURL,
			httpbinding.WithAccept(acceptsDID), httpbinding.WithHTTPClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: vcProviderConf.TLS,
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
		vdr.WithVDR(jwk.New()),
		vdr.WithVDR(
			&webVDR{
				http: &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: vcProviderConf.TLS,
					},
				},
				VDR: web.New(),
			},
		),
	)

	return vdr.New(opts...), nil
}

type kmsProvider struct {
	store             kmsapi.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kmsapi.Store {
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
