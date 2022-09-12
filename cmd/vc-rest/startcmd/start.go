/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	oapimw "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/gorilla/mux"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	restlogspec "github.com/trustbloc/edge-core/pkg/restapi/logspec"

	"github.com/trustbloc/vcs/api/spec"
	"github.com/trustbloc/vcs/cmd/common"
	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	issuersvc "github.com/trustbloc/vcs/pkg/issuer"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	restholder "github.com/trustbloc/vcs/pkg/restapi/v0.1/holder"
	holderops "github.com/trustbloc/vcs/pkg/restapi/v0.1/holder/operation"
	restissuer "github.com/trustbloc/vcs/pkg/restapi/v0.1/issuer"
	issuerops "github.com/trustbloc/vcs/pkg/restapi/v0.1/issuer/operation"
	restverifier "github.com/trustbloc/vcs/pkg/restapi/v0.1/verifier"
	verifierops "github.com/trustbloc/vcs/pkg/restapi/v0.1/verifier/operation"
	"github.com/trustbloc/vcs/pkg/restapi/v1/healthcheck"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	verifierv1 "github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/issuerstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/verifierstore"
	verifiersvc "github.com/trustbloc/vcs/pkg/verifier"
)

const (
	healthCheckEndpoint = "/healthcheck"
	cslSize             = 1000
)

var logger = log.New("vc-rest")

type httpServer interface {
	ListenAndServe() error
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

			if conf.StartupParameters.useEchoHandler {
				var e *echo.Echo

				e, err = buildEchoHandler(conf)
				if err != nil {
					return fmt.Errorf("failed to build echo handler: %w", err)
				}

				opts = append(opts, WithHTTPHandler(e))
			}

			return startServer(conf, opts...)
		},
	}
}

// buildEchoHandler builds an HTTP handler based on Echo web framework (https://echo.labstack.com).
func buildEchoHandler(conf *Configuration) (*echo.Echo, error) {
	e := echo.New()
	e.HideBanner = true

	e.HTTPErrorHandler = resterr.HTTPErrorHandler

	// Middlewares
	e.Use(echomw.Logger())
	e.Use(echomw.Recover())

	swagger, err := spec.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("failed to get openapi spec: %w", err)
	}

	swagger.Servers = nil // skip validating server names matching

	e.Use(oapimw.OapiRequestValidator(swagger))

	// Handlers
	healthcheck.RegisterHandlers(e, &healthcheck.Controller{})

	mongodbClient, err := mongodb.New(conf.StartupParameters.dbParameters.databaseURL,
		conf.StartupParameters.dbParameters.databasePrefix+"vcs",
		5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client: %w", err)
	}

	kmsRegistry := kms.NewRegistry(&kms.Config{
		KMSType:           kms.Local,
		SecretLockKeyPath: conf.StartupParameters.kmsParameters.secretLockKeyPath,
		DBType:            conf.StartupParameters.dbParameters.databaseType,
		DBURL:             conf.StartupParameters.dbParameters.databaseURL,
		DBPrefix:          conf.StartupParameters.dbParameters.databasePrefix,
	})

	// Issuer Profile Management API
	issuerProfileStore := issuerstore.NewProfileStore(mongodbClient)
	issuerProfileSvc := issuersvc.NewProfileService(&issuersvc.ServiceConfig{
		ProfileStore: issuerProfileStore,
		DIDCreator: did.NewCreator(&did.CreatorConfig{
			VDR:             conf.VDR,
			DIDAnchorOrigin: conf.StartupParameters.didAnchorOrigin,
		}),
		KMSRegistry: kmsRegistry,
	})

	vcCrypto := crypto.New(conf.VDR, conf.DocumentLoader)

	vcStatusManager, err := cslstatus.New(conf.Storage.provider, cslSize, vcCrypto, conf.DocumentLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	issuecredentialsvc := issuecredential.New(&issuecredential.Config{
		VCStatusManager: vcStatusManager,
		Crypto:          vcCrypto,
	})

	issuerv1.RegisterHandlers(e, issuerv1.NewController(&issuerv1.Config{
		ProfileSvc:             issuerProfileSvc,
		KMSRegistry:            kmsRegistry,
		DocumentLoader:         conf.DocumentLoader,
		IssueCredentialService: issuecredentialsvc,
	}))

	// Verifier Profile Management API
	verifierProfileStore := verifierstore.NewProfileStore(mongodbClient)
	verifierProfileSvc := verifiersvc.NewProfileService(verifierProfileStore)
	verifierController := verifierv1.NewController(verifierProfileSvc)

	verifierv1.RegisterHandlers(e, verifierController)

	return e, nil
}

func startServer(conf *Configuration, opts ...StartOpts) error {
	o := &startOpts{}

	for _, opt := range opts {
		opt(o)
	}

	if o.handler == nil { // default handler is based on gorilla/mux
		h, err := buildHandler(conf)
		if err != nil {
			return fmt.Errorf("failed to build default handler: %w", err)
		}

		o.handler = h
	}

	if o.server == nil {
		o.server = &http.Server{
			Addr:    conf.StartupParameters.hostURL,
			Handler: o.handler,
		}
	}

	logger.Infof("Starting vc-rest server on host %s", conf.StartupParameters.hostURL)

	return o.server.ListenAndServe()
}

// buildHandler builds an HTTP handler based on gorilla/mux router.
func buildHandler(conf *Configuration) (http.Handler, error) {
	if conf.StartupParameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, conf.StartupParameters.logLevel)
	}

	router := mux.NewRouter()

	if conf.StartupParameters.token != "" {
		router.Use(authorizationMiddleware(conf.StartupParameters.token))
	}

	externalHostURL := conf.StartupParameters.hostURL
	if conf.StartupParameters.hostURLExternal != "" {
		externalHostURL = conf.StartupParameters.hostURLExternal
	}

	issuerService, err := restissuer.New(&issuerops.Config{
		StoreProvider:   conf.Storage.provider,
		KeyManager:      conf.LocalKMS,
		Crypto:          conf.Crypto,
		VDRI:            conf.VDR,
		HostURL:         externalHostURL,
		Domain:          conf.StartupParameters.blocDomain,
		TLSConfig:       &tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12},
		DIDAnchorOrigin: conf.StartupParameters.didAnchorOrigin,
		DocumentLoader:  conf.DocumentLoader,
	})
	if err != nil {
		return nil, err
	}

	holderService, err := restholder.New(&holderops.Config{
		TLSConfig: &tls.Config{
			RootCAs:    conf.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
		StoreProvider:   conf.Storage.provider,
		KeyManager:      conf.LocalKMS,
		Crypto:          conf.Crypto,
		VDRI:            conf.VDR,
		Domain:          conf.StartupParameters.blocDomain,
		DIDAnchorOrigin: conf.StartupParameters.didAnchorOrigin,
		DocumentLoader:  conf.DocumentLoader,
	})
	if err != nil {
		return nil, err
	}

	verifierService, err := restverifier.New(&verifierops.Config{
		StoreProvider:  conf.Storage.provider,
		TLSConfig:      &tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12},
		VDRI:           conf.VDR,
		RequestTokens:  conf.StartupParameters.requestTokens,
		DocumentLoader: conf.DocumentLoader,
	})
	if err != nil {
		return nil, err
	}

	if conf.StartupParameters.mode == string(issuer) || conf.StartupParameters.mode == string(combined) {
		for _, handler := range issuerService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	if conf.StartupParameters.mode == string(verifier) || conf.StartupParameters.mode == string(combined) {
		for _, handler := range verifierService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	if conf.StartupParameters.mode == string(holder) || conf.StartupParameters.mode == string(combined) {
		for _, handler := range holderService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	for _, handler := range restlogspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// handlers for JSON-LD context operations
	for _, handler := range ldrest.New(ldsvc.New(conf.LDContextStore)).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	return constructCORSHandler(router), nil
}

func authorizationMiddleware(token string) mux.MiddlewareFunc {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validateAuthorizationBearerToken(w, r, token) {
				next.ServeHTTP(w, r)
			}
		})
	}

	return middleware
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

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

func healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		logger.Errorf("healthcheck response failure, %s", err)
	}
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}
