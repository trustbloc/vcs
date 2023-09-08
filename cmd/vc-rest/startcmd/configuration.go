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

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	ariesdid "github.com/hyperledger/aries-framework-go/component/models/did"
	vdrpkg "github.com/hyperledger/aries-framework-go/component/vdr"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	"github.com/hyperledger/aries-framework-go/component/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/component/vdr/key"
	"github.com/hyperledger/aries-framework-go/component/vdr/web"
	tlsutils "github.com/trustbloc/cmdutil-go/pkg/utils/tls"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/observability/tracing"
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
	VDR               vdrapi.Registry
	Tracer            trace.Tracer
	IsTraceEnabled    bool
	StartupParameters *startupParameters
}

func prepareConfiguration(parameters *startupParameters, tracer trace.Tracer) (*Configuration, error) {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParameters.systemCertPool, parameters.tlsParameters.caCerts)
	if err != nil {
		return nil, err
	}

	vdr, err := createVDRI(parameters.universalResolverURL, parameters.orbDomain,
		&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}

	return &Configuration{
		RootCAs:           rootCAs,
		VDR:               vdr,
		Tracer:            tracer,
		IsTraceEnabled:    parameters.tracingParams.exporter != tracing.None,
		StartupParameters: parameters,
	}, nil
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

	// add vdr
	opts = append(opts, vdrpkg.WithVDR(longformVDR), vdrpkg.WithVDR(key.New()), vdrpkg.WithVDR(jwk.New()),
		vdrpkg.WithVDR(&webVDR{
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
	return method == didMethodION
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
