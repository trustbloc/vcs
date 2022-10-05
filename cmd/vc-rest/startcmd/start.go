/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"github.com/trustbloc/vcs/pkg/restapi/v1/devapi"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"net/http"

	oapimw "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/api/spec"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/kms"
	profilereader "github.com/trustbloc/vcs/pkg/profile/reader"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/healthcheck"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/mw"
	verifierv1 "github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
)

const (
	healthCheckEndpoint = "/healthcheck"
	cslSize             = 1000
)

var logger = log.New("vc-rest")

type httpServer interface {
	ListenAndServe() error
	ListenAndServeTLS(certFile, keyFile string) error
}

type startOpts struct {
	server  httpServer
	handler http.Handler
}

// StartOpts configures the vc-rest server with custom options.
type StartOpts func(opts *startOpts)

// WithHTTPServer sets the custom HTTP server.
func WithHTTPServer(server httpServer) StartOpts {
	return func(opts *startOpts) {
		opts.server = server
	}
}

// WithHTTPHandler sets the custom HTTP handler.
func WithHTTPHandler(handler http.Handler) StartOpts {
	return func(opts *startOpts) {
		opts.handler = handler
	}
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(opts ...StartOpts) *cobra.Command {
	startCmd := createStartCmd(opts...)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(opts ...StartOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start vc-rest",
		Long:  "Start vc-rest inside the vcs",
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := getStartupParameters(cmd)
			if err != nil {
				return fmt.Errorf("failed to get startup parameters: %w", err)
			}

			conf, err := prepareConfiguration(params)
			if err != nil {
				return fmt.Errorf("failed to prepare configuration: %w", err)
			}

			var e *echo.Echo

			e, err = buildEchoHandler(conf, cmd)
			if err != nil {
				return fmt.Errorf("failed to build echo handler: %w", err)
			}

			opts = append(opts, WithHTTPHandler(e))

			return startServer(conf, opts...)
		},
	}
}

// buildEchoHandler builds an HTTP handler based on Echo web framework (https://echo.labstack.com).
func buildEchoHandler(conf *Configuration, cmd *cobra.Command) (*echo.Echo, error) {
	e := echo.New()
	e.HideBanner = true

	e.HTTPErrorHandler = resterr.HTTPErrorHandler

	// Middlewares
	e.Use(echomw.Logger())
	e.Use(echomw.Recover())
	e.Use(echomw.CORS())

	if conf.StartupParameters.token != "" {
		e.Use(mw.APIKeyAuth(conf.StartupParameters.token))
	}

	swagger, err := spec.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("failed to get openapi spec: %w", err)
	}

	swagger.Servers = nil // skip validating server names matching

	e.Use(oapimw.OapiRequestValidator(swagger))

	// Handlers
	healthcheck.RegisterHandlers(e, &healthcheck.Controller{})

	tlsConfig := &tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12}

	defaultVCSKeyManager, err := kms.NewAriesKeyManager(&kms.Config{
		KMSType:           conf.StartupParameters.kmsParameters.kmsType,
		Endpoint:          conf.StartupParameters.kmsParameters.kmsEndpoint,
		Region:            conf.StartupParameters.kmsParameters.kmsRegion,
		HTTPClient:        http.DefaultClient, // TODO change to custom http client
		SecretLockKeyPath: conf.StartupParameters.kmsParameters.secretLockKeyPath,
		DBType:            conf.StartupParameters.dbParameters.databaseType,
		DBURL:             conf.StartupParameters.dbParameters.databaseURL,
		DBPrefix:          conf.StartupParameters.dbParameters.databasePrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default kms: %w", err)
	}

	kmsRegistry := kms.NewRegistry(defaultVCSKeyManager)

	// Issuer Profile Management API
	issuerProfileSvc, err := profilereader.NewIssuerReader(&profilereader.Config{
		TLSConfig:   tlsConfig,
		KMSRegistry: kmsRegistry,
		CMD:         cmd,
	})
	if err != nil {
		return nil, err
	}

	vcCrypto := crypto.New(conf.VDR, conf.DocumentLoader)

	vcStatusManager, err := cslstatus.New(conf.Storage.provider, cslSize, vcCrypto, conf.DocumentLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	issuecredentialsvc := issuecredential.New(&issuecredential.Config{
		VCStatusManager: vcStatusManager,
		Crypto:          vcCrypto,
		KMSRegistry:     kmsRegistry,
	})

	issuerv1.RegisterHandlers(e, issuerv1.NewController(&issuerv1.Config{
		ProfileSvc:             issuerProfileSvc,
		KMSRegistry:            kmsRegistry,
		DocumentLoader:         conf.DocumentLoader,
		IssueCredentialService: issuecredentialsvc,
	}))

	// Verifier Profile Management API
	verifierProfileSvc, err := profilereader.NewVerifierReader(
		&profilereader.Config{
			TLSConfig:   tlsConfig,
			KMSRegistry: kmsRegistry,
			CMD:         cmd,
		})
	if err != nil {
		return nil, err
	}

	vcStatusManagerSvc := credentialstatus.New(&credentialstatus.Config{
		VDR:            conf.VDR,
		TLSConfig:      &tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12},
		RequestTokens:  conf.StartupParameters.requestTokens,
		DocumentLoader: conf.DocumentLoader,
	})
	verifyCredentialSvc := verifycredential.New(&verifycredential.Config{
		VcStatusManager: vcStatusManagerSvc,
		DocumentLoader:  conf.DocumentLoader,
		VDR:             conf.VDR,
	})
	verifierController := verifierv1.NewController(&verifierv1.Config{
		VerifyCredentialSvc: verifyCredentialSvc,
		ProfileSvc:          verifierProfileSvc,
		KMSRegistry:         kmsRegistry,
		DocumentLoader:      conf.DocumentLoader,
		VDR:                 conf.VDR,
	})

	verifierv1.RegisterHandlers(e, verifierController)

	didConfigSvc := didconfiguration.New(&didconfiguration.Config{
		VerifierProfileService:  verifierProfileSvc,
		IssuerProfileService:    issuerProfileSvc,
		IssuerCredentialService: issuecredentialsvc,
	})

	if conf.StartupParameters.devMode {
		devController := devapi.NewController(&devapi.Config{
			DidConfigService: didConfigSvc,
		})

		devapi.RegisterHandlers(e, devController)
	}

	return e, nil
}

func startServer(conf *Configuration, opts ...StartOpts) error {
	o := &startOpts{}

	for _, opt := range opts {
		opt(o)
	}

	if o.server == nil {
		o.server = &http.Server{
			Addr:    conf.StartupParameters.hostURL,
			Handler: o.handler,
		}
	}

	logger.Infof("Starting vc-rest server on host %s", conf.StartupParameters.hostURL)

	if conf.StartupParameters.tlsParameters.serveKeyPath != "" &&
		conf.StartupParameters.tlsParameters.serveCertPath != "" {
		return o.server.ListenAndServeTLS(conf.StartupParameters.tlsParameters.serveCertPath,
			conf.StartupParameters.tlsParameters.serveKeyPath)
	}

	return o.server.ListenAndServe()
}

func validateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, token string) bool {
	if r.RequestURI == healthCheckEndpoint {
		return true
	}

	actHdr := r.Header.Get("Authorization")
	expHdr := "Bearer " + token

	if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

		return false
	}

	return true
}
