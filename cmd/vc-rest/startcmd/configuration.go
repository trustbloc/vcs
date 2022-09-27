/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	jsonld "github.com/piprate/json-gold/ld"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/vcs/pkg/ld"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"
	mongodbvcsprovider "github.com/trustbloc/vcs/pkg/storage/mongodbprovider"
)

// mode in which to run the vc-rest service
type mode string

const (
	verifier mode = "verifier"
	issuer   mode = "issuer"
	holder   mode = "holder"
	combined mode = "combined"
)

// Configuration for the vc-rest API server.
type Configuration struct {
	RootCAs           *x509.CertPool
	Storage           *vcStorageProviders
	VDR               vdrapi.Registry
	DocumentLoader    jsonld.DocumentLoader
	LDContextStore    *ld.StoreProvider
	StartupParameters *startupParameters
}

func prepareConfiguration(parameters *startupParameters) (*Configuration, error) {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParameters.systemCertPool, parameters.tlsParameters.caCerts)
	if err != nil {
		return nil, err
	}

	storeProviders, err := createStoreProviders(parameters)
	if err != nil {
		return nil, err
	}

	vdr, err := createVDRI(parameters.universalResolverURL,
		&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, parameters.blocDomain,
		parameters.requestTokens["sidetreeToken"])
	if err != nil {
		return nil, err
	}

	ldStore, err := ld.NewStoreProvider(storeProviders.provider)
	if err != nil {
		return nil, err
	}

	loader, err := createJSONLDDocumentLoader(ldStore, rootCAs, parameters.contextProviderURLs,
		parameters.contextEnableRemote)
	if err != nil {
		return nil, err
	}

	return &Configuration{
		RootCAs:           rootCAs,
		Storage:           storeProviders,
		VDR:               vdr,
		DocumentLoader:    loader,
		LDContextStore:    ldStore,
		StartupParameters: parameters,
	}, nil
}

type vcStorageProviders struct {
	provider vcsstorage.Provider
}

func createStoreProviders(parameters *startupParameters) (*vcStorageProviders, error) {
	var edgeServiceProvs vcStorageProviders

	var err error

	edgeServiceProvs.provider, err = createMainStoreProvider(parameters)
	if err != nil {
		return nil, err
	}

	return &edgeServiceProvs, nil
}

func createMainStoreProvider(parameters *startupParameters) (vcsstorage.Provider, error) { //nolint: dupl
	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return nil, err
		}

		return mongodbvcsprovider.New(mongoDBProvider), nil
	default:
		return nil, fmt.Errorf("%s is not a valid database type."+
			" run start --help to see the available options", parameters.dbParameters.databaseType)
	}
}

func createVDRI(universalResolver string, tlsConfig *tls.Config, blocDomain,
	sidetreeAuthToken string) (vdrapi.Registry, error) {
	var opts []vdrpkg.Option

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
		opts = append(opts, vdrpkg.WithVDR(universalResolverVDRI))
	}

	vdr, err := orb.New(nil, orb.WithDomain(blocDomain), orb.WithTLSConfig(tlsConfig),
		orb.WithAuthToken(sidetreeAuthToken))
	if err != nil {
		return nil, err
	}

	// add bloc vdr
	opts = append(opts, vdrpkg.WithVDR(vdr), vdrpkg.WithVDR(key.New()))

	return vdrpkg.New(opts...), nil
}

// acceptsDID returns if given did method is accepted by VC REST api
func acceptsDID(method string) bool {
	return method == didMethodVeres || method == didMethodElement || method == didMethodSov ||
		method == didMethodWeb || method == didMethodFactom
}

func createJSONLDDocumentLoader(ldStore *ld.StoreProvider, rootCAs *x509.CertPool,
	providerURLs []string, contextEnableRemote bool) (jsonld.DocumentLoader, error) {
	var loaderOpts []ariesld.DocumentLoaderOpts

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
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
