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
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	ariesapi "github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	tlsutils "github.com/trustbloc/cmdutil-go/pkg/utils/tls"

	"github.com/trustbloc/vcs/pkg/ld"
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

	edgeStoreProviders, err := createEdgeStoreProviders(parameters)
	if err != nil {
		return nil, err
	}

	vdr, err := createVDRI(parameters.universalResolverURL, parameters.orbDomain,
		&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}

	ldStore, err := ld.NewStoreProvider(edgeStoreProviders.provider)
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
		Storage:           edgeStoreProviders,
		VDR:               vdr,
		DocumentLoader:    loader,
		LDContextStore:    ldStore,
		StartupParameters: parameters,
	}, nil
}

type vcStorageProviders struct {
	provider ariesapi.Provider
}

func createEdgeStoreProviders(parameters *startupParameters) (*vcStorageProviders, error) {
	var edgeServiceProvs vcStorageProviders

	var err error

	edgeServiceProvs.provider, err = createEdgeStoreProvider(parameters)
	if err != nil {
		return nil, err
	}

	return &edgeServiceProvs, nil
}

func createEdgeStoreProvider(parameters *startupParameters) (ariesapi.Provider, error) { //nolint: dupl
	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		return ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))

	default:
		return nil, fmt.Errorf("%s is not a valid database type."+
			" run start --help to see the available options", parameters.dbParameters.databaseType)
	}
}

func createVDRI(universalResolver, orbDomain string, tlsConfig *tls.Config) (vdrapi.Registry, error) {
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

	longformVDR, err := longform.New()
	if err != nil {
		return nil, err
	}

	orbVDR, err := orb.New(nil, orb.WithDomain(orbDomain), orb.WithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}

	// add bloc vdr
	opts = append(opts, vdrpkg.WithVDR(longformVDR), vdrpkg.WithVDR(orbVDR),
		vdrpkg.WithVDR(key.New()), vdrpkg.WithVDR(key.New()), vdrpkg.WithVDR(&webVDR{
			http: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				}},
			VDR: web.New(),
		}))

	return vdrpkg.New(opts...), nil
}

// acceptsDID returns if given did method is accepted by VC REST api
func acceptsDID(method string) bool {
	return method == didMethodVeres || method == didMethodElement || method == didMethodSov ||
		method == didMethodWeb || method == didMethodFactom || method == didMethodORB ||
		method == didMethodKey || method == didMethodION
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
