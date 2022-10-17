/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	oapimw "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/api/spec"
	"github.com/trustbloc/vcs/component/event"
	"github.com/trustbloc/vcs/component/oidc/vp"
	"github.com/trustbloc/vcs/internal/pkg/log"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/kms"
	profilereader "github.com/trustbloc/vcs/pkg/profile/reader"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/devapi"
	"github.com/trustbloc/vcs/pkg/restapi/v1/healthcheck"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/mw"
	verifierv1 "github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifycredential/revocation"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vptxstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidcnoncestore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/requestobjectstore"
)

const (
	healthCheckEndpoint  = "/healthcheck"
	oidc4VPCheckEndpoint = "/verifier/interactions/authorization-response"
	cslSize              = 1000
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

	mongodbClient, err := mongodb.New(conf.StartupParameters.dbParameters.databaseURL,
		conf.StartupParameters.dbParameters.databasePrefix+"vcs",
		15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client: %w", err)
	}

	// Create event service
	eventSvc, err := event.Initialize(event.Config{
		TLSConfig: tlsConfig,
		CMD:       cmd,
	})
	if err != nil {
		return nil, err
	}

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

	vcStatusManager, err := credentialstatus.New(conf.Storage.provider, cslSize, vcCrypto, conf.DocumentLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	issueCredentialSvc, err := issuecredential.New(&issuecredential.Config{
		VCStatusManager: vcStatusManager,
		Crypto:          vcCrypto,
		KMSRegistry:     kmsRegistry,
		StorageProvider: conf.Storage.provider,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new issue credential service: %w", err)
	}

	issuerv1.RegisterHandlers(e, issuerv1.NewController(&issuerv1.Config{
		EventSvc:               eventSvc,
		ProfileSvc:             issuerProfileSvc,
		KMSRegistry:            kmsRegistry,
		DocumentLoader:         conf.DocumentLoader,
		IssueCredentialService: issueCredentialSvc,
		VcStatusManager:        vcStatusManager,
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

	revocationListGetterSvc := revocation.New(&revocation.Config{
		VDR:            conf.VDR,
		TLSConfig:      tlsConfig,
		RequestTokens:  conf.StartupParameters.requestTokens,
		DocumentLoader: conf.DocumentLoader,
	})

	verifyCredentialSvc := verifycredential.New(&verifycredential.Config{
		RevocationVCGetter: revocationListGetterSvc,
		DocumentLoader:     conf.DocumentLoader,
		VDR:                conf.VDR,
	})
	verifyPresentationSvc := verifypresentation.New(&verifypresentation.Config{
		VcVerifier:     verifyCredentialSvc,
		DocumentLoader: conf.DocumentLoader,
		VDR:            conf.VDR,
	})
	oidc4vpTxStore := oidc4vptxstore.NewTxStore(mongodbClient, conf.DocumentLoader)
	oidcNonceStore := oidcnoncestore.New(mongodbClient)
	requestObjStore := requestobjectstore.NewStore(mongodbClient)
	//TODO: add parameter to specify live time of interaction request object
	requestObjStoreEndpoint := conf.StartupParameters.hostURLExternal + "/request-object/"
	oidc4vpTxManager := oidc4vp.NewTxManager(oidcNonceStore, oidc4vpTxStore, 15*time.Minute)
	requestObjectStoreService := vp.NewRequestObjectStore(requestObjStore, requestObjStoreEndpoint)
	oidc4vpService := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:                 eventSvc,
		TransactionManager:       oidc4vpTxManager,
		RequestObjectPublicStore: requestObjectStoreService,
		KMSRegistry:              kmsRegistry,
		VDR:                      conf.VDR,
		DocumentLoader:           conf.DocumentLoader,
		ProfileService:           verifierProfileSvc,
		PresentationVerifier:     verifyPresentationSvc,
		RedirectURL:              conf.StartupParameters.hostURLExternal + oidc4VPCheckEndpoint,
		TokenLifetime:            15 * time.Minute,
	})
	verifierController := verifierv1.NewController(&verifierv1.Config{
		VerifyCredentialSvc: verifyCredentialSvc,
		ProfileSvc:          verifierProfileSvc,
		KMSRegistry:         kmsRegistry,
		DocumentLoader:      conf.DocumentLoader,
		VDR:                 conf.VDR,
		OIDCVPService:       oidc4vpService,
	})

	verifierv1.RegisterHandlers(e, verifierController)

	didConfigSvc := didconfiguration.New(&didconfiguration.Config{
		VerifierProfileService:  verifierProfileSvc,
		IssuerProfileService:    issuerProfileSvc,
		IssuerCredentialService: issueCredentialSvc,
		KmsRegistry:             kmsRegistry,
	})

	if conf.StartupParameters.devMode {
		devController := devapi.NewController(&devapi.Config{
			DidConfigService:          didConfigSvc,
			RequestObjectStoreService: requestObjectStoreService,
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

	logger.Info("Starting vc-rest server on host", log.WithHostURL(conf.StartupParameters.hostURL))

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
