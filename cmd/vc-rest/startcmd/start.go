/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alexliesenfeld/health"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	oapimw "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/dgraph-io/ristretto"
	"github.com/trustbloc/did-go/doc/ld/documentloader"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	jsonld "github.com/piprate/json-gold/ld"
	echopprof "github.com/sevenNt/echo-pprof"
	"github.com/spf13/cobra"
	"github.com/trustbloc/did-go/doc/ld/context/remote"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/trustbloc/vcs/api/spec"
	"github.com/trustbloc/vcs/component/credentialstatus"
	echoprometheus "github.com/trustbloc/vcs/component/echo"
	"github.com/trustbloc/vcs/component/event"
	"github.com/trustbloc/vcs/component/healthchecks"
	"github.com/trustbloc/vcs/component/oidc/vp"
	"github.com/trustbloc/vcs/component/otp"
	"github.com/trustbloc/vcs/pkg/cslmanager"
	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/doc/validator/jsonschema"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/observability/health/healthutil"
	metricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
	promMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/prometheus"
	"github.com/trustbloc/vcs/pkg/observability/tracing"
	credentialstatustracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/credentialstatus/component"
	issuecredentialtracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/issuecredential"
	fositetracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/oauth2provider"
	oidc4citracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/oidc4ci"
	oidc4vptracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/oidc4vp"
	verifycredentialtracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/verifycredential"
	verifypresentationtracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/verifypresentation"
	profilereader "github.com/trustbloc/vcs/pkg/profile/reader"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/devapi"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/logapi"
	"github.com/trustbloc/vcs/pkg/restapi/v1/mw"
	oidc4civ1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	oidc4vpv1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vp"
	verifierv1 "github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	"github.com/trustbloc/vcs/pkg/restapi/v1/version"
	"github.com/trustbloc/vcs/pkg/service/clientidscheme"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	credentialstatustypes "github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
	wellknownfetcher "github.com/trustbloc/vcs/pkg/service/wellknown/fetcher"
	wellknownprovider "github.com/trustbloc/vcs/pkg/service/wellknown/provider"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cslindexstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cslvcstore"
	claimdatastoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4ciclaimdatastore"
	oidc4cinoncestoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4cinoncestore"
	oidc4cistatestoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4cistatestore"
	oidc4vpclaimsstoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vpclaimsstore"
	oidc4vpnoncestoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vpnoncestore"
	oidc4vptxstoremongo "github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vptxstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/requestobjectstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/vcstatusstore"
	"github.com/trustbloc/vcs/pkg/storage/redis"
	redisclient "github.com/trustbloc/vcs/pkg/storage/redis"
	oidc4ciclaimdatastoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4ciclaimdatastore"
	oidc4cinoncestoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4cinoncestore"
	oidc4cistatestoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4cistatestore"
	oidc4vpclaimsstoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4vpclaimsstore"
	oidc4vpnoncestoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4vpnoncestore"
	oidc4vptxstoreredis "github.com/trustbloc/vcs/pkg/storage/redis/oidc4vptxstore"
	"github.com/trustbloc/vcs/pkg/storage/s3/credentialoffer"
	cslstores3 "github.com/trustbloc/vcs/pkg/storage/s3/cslvcstore"
	requestobjectstore2 "github.com/trustbloc/vcs/pkg/storage/s3/requestobjectstore"
)

const (
	healthCheckEndpoint             = "/healthcheck"
	statusEndpoint                  = "/status"
	oidc4VPCheckEndpoint            = "/oidc/present"
	defaultGracefulShutdownDuration = 1 * time.Second
	defaultHealthCheckTimeout       = 5 * time.Second
	cslSize                         = 10000
	devApiRequestObjectEndpoint     = "/request-object/:uuid"
	devApiDidConfigEndpoint         = "/:profileType/profiles/:profileID/:profileVersion/well-known/did-config"
	logLevelsEndpoint               = "/loglevels"
	profilerEndpoints               = "/debug/pprof"
	versionEndpoint                 = "/version/system"
	versionSystemEndpoint           = "/version"
)

var logger = log.New("vc-rest")

type httpServer interface {
	ListenAndServe() error
	ListenAndServeTLS(certFile, keyFile string) error
}

type startOpts struct {
	server        httpServer
	handler       http.Handler
	version       string
	serverVersion string
}

// StartOpts configures the vc-rest server with custom options.
type StartOpts func(opts *startOpts)

// WithHTTPServer sets the custom HTTP server.
func WithHTTPServer(server httpServer) StartOpts {
	return func(opts *startOpts) {
		opts.server = server
	}
}

// WithVersion sets the custom HTTP server.
func WithVersion(version string) StartOpts {
	return func(opts *startOpts) {
		opts.version = version
	}
}

// WithServerVersion sets the custom HTTP server.
func WithServerVersion(version string) StartOpts {
	return func(opts *startOpts) {
		opts.serverVersion = version
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
			sig := make(chan os.Signal, 1)
			go func() {
				<-cmd.Context().Done()
				sig <- syscall.SIGINT
			}()

			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

			params, err := getStartupParameters(cmd)
			if err != nil {
				return fmt.Errorf("failed to get startup parameters: %w", err)
			}

			if params.logLevels != "" {
				if e := log.SetSpec(params.logLevels); e != nil {
					logger.Warn("Error setting logging spec.", log.WithError(e))
				}
			}

			traceParams := params.tracingParams

			shutdownTracer, tracer, err := tracing.Initialize(traceParams.exporter, traceParams.serviceName)
			if err != nil {
				return fmt.Errorf("initialize tracing: %w", err)
			}
			defer shutdownTracer()

			conf, err := prepareConfiguration(params, tracer)
			if err != nil {
				return fmt.Errorf("failed to prepare configuration: %w", err)
			}

			internalEchoAddress := conf.StartupParameters.prometheusMetricsProviderParams.url
			internalEcho, ready := buildInternalEcho(conf, cmd)

			go func() {
				if internalErr := internalEcho.Start(internalEchoAddress); internalErr != nil &&
					internalErr != http.ErrServerClosed {
					panic(fmt.Errorf("can not start internal echo handler on address [%v] with error : %w",
						internalEchoAddress, internalErr))
				}
			}()

			var e *echo.Echo
			e, err = buildEchoHandler(conf, cmd, internalEcho, buildOptions(opts...))
			if err != nil {
				return fmt.Errorf("failed to build echo handler: %w", err)
			}

			if conf.StartupParameters.enableProfiler {
				logger.Warn("pprof profiler enabled")
				echopprof.Wrap(e)
			}

			opts = append(opts, WithHTTPHandler(e))

			go func() {
				if internalErr := startServer(conf, opts...); internalErr != nil &&
					internalErr != http.ErrServerClosed {
					panic(internalErr)
				}
			}()

			ready.Ready(true)
			sg := <-sig
			ready.Ready(false)
			shutdownDuration := getGracefulSleepDuration()

			logger.Info(fmt.Sprintf("[Graceful Shutdown] GOT SIGNAL %v", sg.String()))
			logger.Info(fmt.Sprintf("[Graceful Shutdown] Sleeping for %v", shutdownDuration.String()))
			time.Sleep(shutdownDuration)
			_ = internalEcho.Close()
			logger.Info("[Graceful Shutdown] Exit")

			return nil
		},
	}
}

func getGracefulSleepDuration() time.Duration {
	currentSec := os.Getenv("VC_REST_GRACEFUL_SHUTDOWN_DELAY_SEC")

	if len(currentSec) > 0 {
		if v, err := strconv.Atoi(currentSec); err == nil {
			return time.Duration(v) * time.Second
		}
	}

	return defaultGracefulShutdownDuration
}

func createEcho() *echo.Echo {
	e := echo.New()
	e.HideBanner = true

	// middlewares
	e.Use(echomw.Logger())
	e.Use(echomw.Recover())
	e.Use(echomw.CORS())

	return e
}

func buildInternalEcho(conf *Configuration, cmd *cobra.Command) (*echo.Echo, *readiness) {
	e := echo.New()
	e.HideBanner = true

	e.Use(echomw.Recover())

	e.GET(healthCheckEndpoint, func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	tlsConfig := &tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12}

	checksConfig := &healthchecks.Config{
		MongoDBURL: conf.StartupParameters.dbParameters.databaseURL,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		Cmd:       cmd,
		TLSConfig: tlsConfig,
	}

	if conf.StartupParameters.transientDataParams.storeType == redisStore {
		checksConfig.RedisParameters = &healthchecks.RedisParameters{
			Addrs:      conf.StartupParameters.redisParameters.addrs,
			MasterName: conf.StartupParameters.redisParameters.masterName,
			Password:   conf.StartupParameters.redisParameters.password,
			DisableTLS: conf.StartupParameters.redisParameters.disableTLS,
		}
	}

	var awsKeys []healthchecks.AWSKMSKey

	if !conf.StartupParameters.dataEncryptionDisabled {
		awsKeys = append(awsKeys, healthchecks.AWSKMSKey{
			Region: conf.StartupParameters.kmsParameters.kmsRegion,
			ID:     conf.StartupParameters.dataEncryptionKeyID,
		})
	}

	if len(awsKeys) > 0 {
		checksConfig.AWSKMSKeys = awsKeys
	}

	var s3Buckets []healthchecks.S3Bucket

	if strings.ToLower(conf.StartupParameters.requestObjectRepositoryType) == "s3" {
		s3Buckets = append(s3Buckets, healthchecks.S3Bucket{
			Region: conf.StartupParameters.requestObjectRepositoryS3Region,
			Name:   conf.StartupParameters.requestObjectRepositoryS3Bucket,
		})
	}

	if strings.ToLower(conf.StartupParameters.cslStoreType) == "s3" {
		s3Buckets = append(s3Buckets, healthchecks.S3Bucket{
			Region: conf.StartupParameters.cslStoreS3Region,
			Name:   conf.StartupParameters.cslStoreS3Bucket,
		})
	}

	if conf.StartupParameters.credentialOfferRepositoryS3Bucket != "" {
		s3Buckets = append(s3Buckets, healthchecks.S3Bucket{
			Region: conf.StartupParameters.credentialOfferRepositoryS3Region,
			Name:   conf.StartupParameters.credentialOfferRepositoryS3Bucket,
		})
	}

	if len(s3Buckets) > 0 {
		checksConfig.S3Buckets = s3Buckets
	}

	checks := healthchecks.Get(checksConfig)

	if len(checks) > 0 {
		opts := []health.CheckerOption{
			health.WithTimeout(defaultHealthCheckTimeout),
		}

		for _, check := range checks {
			opts = append(opts, health.WithCheck(check))
		}

		m := map[string]healthutil.ResponseTimeState{}

		opts = append(opts, health.WithInterceptors(healthutil.ResponseTimeInterceptor(m)))

		healthChecker := health.NewChecker(opts...)

		e.GET(statusEndpoint,
			echo.WrapHandler(
				health.NewHandler(healthChecker,
					health.WithResultWriter(healthutil.NewJSONResultWriter(m)),
					health.WithStatusCodeUp(http.StatusOK),
					health.WithStatusCodeDown(http.StatusServiceUnavailable),
				),
			),
		)
	}

	ready := newReadinessController(e)

	return e, ready
}

// buildEchoHandler builds an HTTP handler based on Echo web framework (https://echo.labstack.com).
func buildEchoHandler(
	conf *Configuration,
	cmd *cobra.Command,
	internalEchoServer *echo.Echo,
	options startOpts,
) (*echo.Echo, error) {
	e := createEcho()

	e.HTTPErrorHandler = resterr.HTTPErrorHandler(conf.Tracer)

	metrics, err := NewMetrics(conf.StartupParameters, e, options)
	if err != nil {
		return nil, err
	}

	if conf.StartupParameters.token != "" {
		e.Use(mw.APIKeyAuth(conf.StartupParameters.token))
	}

	swagger, err := spec.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("failed to get openapi spec: %w", err)
	}

	swagger.Servers = nil // skip validating server names matching

	e.Use(oapimw.OapiRequestValidatorWithOptions(swagger, &oapimw.Options{
		Skipper: OApiSkipper,
	}))

	version.NewController(e, version.Config{
		Version:       options.version,
		ServerVersion: options.serverVersion,
	})

	if conf.IsTraceEnabled {
		e.Use(otelecho.Middleware(""))
	}

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
		AliasPrefix:       conf.StartupParameters.kmsParameters.aliasPrefix,
	}, metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create default kms: %w", err)
	}

	kmsRegistry := kms.NewRegistry(defaultVCSKeyManager)

	var redisClient, redisClientNoTracing *redisclient.Client
	if conf.StartupParameters.transientDataParams.storeType == redisStore {
		defaultOpts := []redisclient.ClientOpt{
			redisclient.WithMasterName(conf.StartupParameters.redisParameters.masterName),
			redisclient.WithPassword(conf.StartupParameters.redisParameters.password)}

		if !conf.StartupParameters.redisParameters.disableTLS {
			defaultOpts = append(defaultOpts, redisclient.WithTLSConfig(
				&tls.Config{RootCAs: conf.RootCAs, MinVersion: tls.VersionTLS12}))
		}

		redisClient, err = redisclient.New(conf.StartupParameters.redisParameters.addrs,
			append(defaultOpts, redisclient.WithTraceProvider(otel.GetTracerProvider()))...)
		if err != nil {
			return nil, fmt.Errorf("failed to create redis client: %w", err)
		}

		redisClientNoTracing, err = redisclient.New(conf.StartupParameters.redisParameters.addrs, defaultOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create redis client no tracing: %w", err)
		}
	}

	mongodbClient, err := mongodb.New(
		conf.StartupParameters.dbParameters.databaseURL,
		conf.StartupParameters.dbParameters.databasePrefix+"vcs_db",
		mongodb.WithTraceProvider(otel.GetTracerProvider()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client: %w", err)
	}

	mongodbClientNoTracing, err := mongodb.New(
		conf.StartupParameters.dbParameters.databaseURL,
		conf.StartupParameters.dbParameters.databasePrefix+"vcs_db",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client (no tracing): %w", err)
	}

	documentLoader, err := createJSONLDDocumentLoader(mongodbClient, tlsConfig,
		conf.StartupParameters.contextProviderURLs, conf.StartupParameters.contextEnableRemote)
	if err != nil {
		return nil, err
	}

	cslVCStore, cslIndexStore, err := createCredentialStatusListStores(
		conf.StartupParameters.cslStoreType,
		conf.StartupParameters.cslStoreS3Region,
		conf.StartupParameters.cslStoreS3Bucket,
		conf.StartupParameters.cslStoreS3HostName,
		mongodbClient,
		conf.IsTraceEnabled)
	if err != nil {
		return nil, err
	}

	vcCrypto := crypto.New(conf.VDR, documentLoader)

	vcStatusStore := vcstatusstore.NewStore(mongodbClient)

	cslManager, err := cslmanager.New(
		&cslmanager.Config{
			CSLVCStore:    cslVCStore,
			CSLIndexStore: cslIndexStore,
			VCStatusStore: vcStatusStore,
			ListSize:      cslSize,
			KMSRegistry:   kmsRegistry,
			Crypto:        vcCrypto,
			ExternalURL:   conf.StartupParameters.hostURLExternal,
		})

	if err != nil {
		return nil, err
	}

	getHTTPClient := func(id metricsProvider.ClientID) *http.Client {
		return newHTTPClient(tlsConfig, conf.StartupParameters, metrics, id)
	}

	openidCredentialIssuerConfigProviderSvc := wellknownprovider.NewService(&wellknownprovider.Config{
		ExternalHostURL: conf.StartupParameters.apiGatewayURL,
		KMSRegistry:     kmsRegistry,
		CryptoJWTSigner: vcCrypto,
	})

	// Issuer Profile Management API
	issuerProfileSvc, err := profilereader.NewIssuerReader(&profilereader.Config{
		OpenidIssuerConfigProvider: openidCredentialIssuerConfigProviderSvc,
		TLSConfig:                  tlsConfig,
		KMSRegistry:                kmsRegistry,
		CMD:                        cmd,
		HTTPClient:                 getHTTPClient(metricsProvider.ClientIssuerProfile),
	})
	if err != nil {
		return nil, err
	}

	// Create event service
	eventSvc, err := event.Initialize(event.Config{
		TLSConfig:      tlsConfig,
		CMD:            cmd,
		CSLVCStore:     cslVCStore,
		ProfileService: issuerProfileSvc,
		KMSRegistry:    kmsRegistry,
		Crypto:         vcCrypto,
		Tracer:         conf.Tracer,
		IsTraceEnabled: conf.IsTraceEnabled,
		DocumentLoader: documentLoader,
	})
	if err != nil {
		return nil, err
	}

	var statusListVCSvc credentialstatustypes.ServiceInterface

	statusListVCSvc, err = credentialstatus.New(&credentialstatus.Config{
		VDR:            conf.VDR,
		HTTPClient:     getHTTPClient(metricsProvider.ClientCredentialStatus),
		RequestTokens:  conf.StartupParameters.requestTokens,
		DocumentLoader: documentLoader,
		CSLVCStore:     cslVCStore,
		CSLManager:     cslManager,
		VCStatusStore:  vcStatusStore,
		ProfileService: issuerProfileSvc,
		KMSRegistry:    kmsRegistry,
		Crypto:         vcCrypto,
		CMD:            cmd,
		ExternalURL:    conf.StartupParameters.hostURLExternal,
		EventPublisher: eventSvc,
		EventTopic:     conf.StartupParameters.credentialStatusEventTopic,
	})
	if err != nil {
		return nil, err
	}

	if conf.IsTraceEnabled {
		statusListVCSvc = credentialstatustracing.Wrap(statusListVCSvc, conf.Tracer)
	}

	var issueCredentialSvc issuecredential.ServiceInterface

	issueCredentialSvc = issuecredential.New(&issuecredential.Config{
		VCStatusManager: statusListVCSvc,
		Crypto:          vcCrypto,
		KMSRegistry:     kmsRegistry,
	})

	if conf.IsTraceEnabled {
		issueCredentialSvc = issuecredentialtracing.Wrap(issueCredentialSvc, conf.Tracer)
	}

	oidc4ciTransactionStore, err := getOIDC4CITransactionStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClient,
		mongodbClient,
		conf.StartupParameters.transientDataParams.oidc4ciTransactionDataTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate oidc4ci transaction store: %w", err)
	}

	oidc4ciClaimDataStore, err := getOIDC4CIClaimDataStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClientNoTracing,
		mongodbClientNoTracing,
		conf.StartupParameters.transientDataParams.claimDataTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate claim data store: %w", err)
	}

	credentialOfferStore, err := createCredentialOfferStore( // credentialOfferStore is optional, so it can be nil
		conf.StartupParameters.credentialOfferRepositoryS3Region,
		conf.StartupParameters.credentialOfferRepositoryS3Bucket,
		conf.StartupParameters.credentialOfferRepositoryS3HostName,
		conf.IsTraceEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate credentialOfferStore: %w", err)
	}

	var oidc4ciService oidc4ci.ServiceInterface

	var dataKeyEncryptor dataprotect.Crypto
	dataKeyEncryptor = defaultVCSKeyManager.Crypto()
	if conf.StartupParameters.dataEncryptionDisabled {
		dataKeyEncryptor = dataprotect.NewNilCrypto()
	}
	claimsDataProtector := dataprotect.NewDataProtector(
		dataKeyEncryptor,
		conf.StartupParameters.dataEncryptionKeyID,
		dataprotect.NewAES(conf.StartupParameters.dataEncryptionKeyLength),
		dataprotect.NewCompressor(conf.StartupParameters.dataEncryptionCompressorAlgo),
	)

	jsonSchemaValidator := jsonschema.NewCachingValidator()

	oidc4ciService, err = oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore:              oidc4ciTransactionStore,
		ClaimDataStore:                oidc4ciClaimDataStore,
		WellKnownService:              wellknownfetcher.NewService(getHTTPClient(metricsProvider.ClientWellKnown)),
		ProfileService:                issuerProfileSvc,
		IssuerVCSPublicHost:           conf.StartupParameters.apiGatewayURL,
		HTTPClient:                    getHTTPClient(metricsProvider.ClientOIDC4CI),
		EventService:                  eventSvc,
		PinGenerator:                  otp.NewPinGenerator(),
		EventTopic:                    conf.StartupParameters.issuerEventTopic,
		PreAuthCodeTTL:                conf.StartupParameters.transientDataParams.claimDataTTL,
		CredentialOfferReferenceStore: credentialOfferStore,
		DataProtector:                 claimsDataProtector,
		KMSRegistry:                   kmsRegistry,
		CryptoJWTSigner:               vcCrypto,
		JSONSchemaValidator:           jsonSchemaValidator,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new oidc4ci service: %w", err)
	}

	if conf.IsTraceEnabled {
		oidc4ciService = oidc4citracing.Wrap(oidc4ciService, conf.Tracer)
	}

	oidc4ciStateStore, err := getOIDC4CIAuthStateStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClient,
		mongodbClient,
		conf.StartupParameters.transientDataParams.oidc4ciAuthStateTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new OIDC4CI state store: %w", err)
	}

	apiKeySecurityProvider, err := securityprovider.NewSecurityProviderApiKey(
		"header",
		"X-API-Key",
		conf.StartupParameters.token,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create security provider for issuer interaction client: %w", err)
	}

	issuerInteractionClient, err := issuerv1.NewClient(
		conf.StartupParameters.hostURLExternal,
		issuerv1.WithHTTPClient(getHTTPClient(metricsProvider.ClientIssuerInteraction)),
		issuerv1.WithRequestEditorFn(apiKeySecurityProvider.Intercept),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer interaction client: %w", err)
	}

	var oauth2Clients []oauth2client.Client

	if conf.StartupParameters.oAuthClientsFilePath != "" {
		if oauth2Clients, err = getOAuth2Clients(conf.StartupParameters.oAuthClientsFilePath); err != nil {
			return nil, fmt.Errorf("failed to get oauth clients: %w", err)
		}
	}

	oauthProvider, fositeStore, err := bootstrapOAuthProvider(
		context.Background(),
		conf.StartupParameters.oAuthSecret,
		conf.StartupParameters.transientDataParams.storeType,
		mongodbClient,
		redisClient,
		oauth2Clients,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new oauth provider: %w", err)
	}

	if conf.IsTraceEnabled {
		oauthProvider = fositetracing.Wrap(oauthProvider, conf.Tracer)
	}

	clientManager := clientmanager.New(
		&clientmanager.Config{
			Store:          fositeStore.(oauth2ClientStore),
			ProfileService: issuerProfileSvc,
		},
	)

	clientIDSchemeSvc := clientidscheme.NewService(&clientidscheme.Config{
		ClientManager:    clientManager,
		HTTPClient:       getHTTPClient(metricsProvider.ClientDiscoverableClientIDScheme),
		ProfileService:   issuerProfileSvc,
		TransactionStore: oidc4ciTransactionStore,
	})

	oidc4civ1.RegisterHandlers(e, oidc4civ1.NewController(&oidc4civ1.Config{
		OAuth2Provider:          oauthProvider,
		StateStore:              oidc4ciStateStore,
		IssuerInteractionClient: issuerInteractionClient,
		ProfileService:          issuerProfileSvc,
		IssuerVCSPublicHost:     conf.StartupParameters.apiGatewayURL, // use api gateway here, as this endpoint will be called by clients
		HTTPClient:              getHTTPClient(metricsProvider.ClientOIDC4CIV1),
		ExternalHostURL:         conf.StartupParameters.hostURLExternal, // use host external as this url will be called internally
		JWTVerifier:             jwt.NewVerifier(jwt.KeyResolverFunc(verifiable.NewVDRKeyResolver(conf.VDR).PublicKeyFetcher())),
		ClientManager:           clientManager,
		ClientIDSchemeService:   clientIDSchemeSvc,
		Tracer:                  conf.Tracer,
	}))

	oidc4vpv1.RegisterHandlers(e, oidc4vpv1.NewController(&oidc4vpv1.Config{
		DefaultHTTPClient: getHTTPClient(metricsProvider.ClientOIDC4PV1),
		ExternalHostURL:   conf.StartupParameters.hostURLExternal, // use host external as this url will be called internally
		Tracer:            conf.Tracer,
	}))

	issuerv1.RegisterHandlers(e, issuerv1.NewController(&issuerv1.Config{
		EventSvc:                   eventSvc,
		ProfileSvc:                 issuerProfileSvc,
		DocumentLoader:             documentLoader,
		IssueCredentialService:     issueCredentialSvc,
		VcStatusManager:            statusListVCSvc,
		OIDC4CIService:             oidc4ciService,
		ExternalHostURL:            conf.StartupParameters.apiGatewayURL,
		Tracer:                     conf.Tracer,
		OpenidIssuerConfigProvider: openidCredentialIssuerConfigProviderSvc,
		JSONSchemaValidator:        jsonSchemaValidator,
	}))

	// Verifier Profile Management API
	verifierProfileSvc, err := profilereader.NewVerifierReader(
		&profilereader.Config{
			TLSConfig:   tlsConfig,
			KMSRegistry: kmsRegistry,
			CMD:         cmd,
			HTTPClient:  getHTTPClient(metricsProvider.ClientVerifierProfile),
		})
	if err != nil {
		return nil, err
	}

	var verifyCredentialSvc verifycredential.ServiceInterface

	verifyCredentialSvc = verifycredential.New(&verifycredential.Config{
		HTTPClient:              getHTTPClient(metricsProvider.ClientCredentialVerifier),
		VCStatusProcessorGetter: statustype.GetVCStatusProcessor,
		StatusListVCResolver:    statusListVCSvc,
		DocumentLoader:          documentLoader,
		VDR:                     conf.VDR,
	})

	if conf.IsTraceEnabled {
		verifyCredentialSvc = verifycredentialtracing.Wrap(verifyCredentialSvc, conf.Tracer)
	}

	var verifyPresentationSvc verifypresentation.ServiceInterface

	verifyPresentationSvc = verifypresentation.New(&verifypresentation.Config{
		VcVerifier:     verifyCredentialSvc,
		DocumentLoader: documentLoader,
		VDR:            conf.VDR,
	})

	if conf.IsTraceEnabled {
		verifyPresentationSvc = verifypresentationtracing.Wrap(verifyPresentationSvc, conf.Tracer)
	}

	oidc4vpTxStore, err := getOIDC4VPTxStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClient,
		mongodbClient,
		documentLoader,
		conf.StartupParameters.transientDataParams.oidc4vpTransactionDataTTL)
	if err != nil {
		return nil, fmt.Errorf("initiate OIDC4VPTxStore: %w", err)
	}

	oidc4vpClaimsStore, err := getOIDC4VPClaimsStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClientNoTracing,
		mongodbClientNoTracing,
		conf.StartupParameters.transientDataParams.oidc4vpReceivedClaimsDataTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate claim data store: %w", err)
	}

	oidc4vpNonceStore, err := getOIDC4VPNonceStore(
		conf.StartupParameters.transientDataParams.storeType,
		redisClient,
		mongodbClient,
		conf.StartupParameters.transientDataParams.oidc4vpNonceStoreDataTTL)
	if err != nil {
		return nil, err
	}

	requestObjStore, err := createRequestObjectStore(
		conf.StartupParameters.requestObjectRepositoryType,
		conf.StartupParameters.requestObjectRepositoryS3Region,
		conf.StartupParameters.requestObjectRepositoryS3Bucket,
		conf.StartupParameters.requestObjectRepositoryS3HostName,
		mongodbClient,
		conf.IsTraceEnabled,
	)
	if err != nil {
		return nil, err
	}

	// TODO: add parameter to specify live time of interaction request object
	requestObjStoreEndpoint := conf.StartupParameters.apiGatewayURL + "/request-object/"
	oidc4vpTxManager := oidc4vp.NewTxManager(
		oidc4vpNonceStore,
		oidc4vpTxStore,
		oidc4vpClaimsStore,
		claimsDataProtector,
		documentLoader,
	)

	requestObjectStoreService := vp.NewRequestObjectStore(requestObjStore, requestObjStoreEndpoint)

	var oidc4vpService oidc4vp.ServiceInterface

	oidc4vpService = oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:                 eventSvc,
		EventTopic:               conf.StartupParameters.verifierEventTopic,
		TransactionManager:       oidc4vpTxManager,
		RequestObjectPublicStore: requestObjectStoreService,
		KMSRegistry:              kmsRegistry,
		VDR:                      conf.VDR,
		DocumentLoader:           documentLoader,
		ProfileService:           verifierProfileSvc,
		PresentationVerifier:     verifyPresentationSvc,
		RedirectURL:              conf.StartupParameters.apiGatewayURL + oidc4VPCheckEndpoint,
		TokenLifetime:            15 * time.Minute,
		Metrics:                  metrics,
	})

	if conf.IsTraceEnabled {
		oidc4vpService = oidc4vptracing.Wrap(oidc4vpService, conf.Tracer)
	}

	verifierController := verifierv1.NewController(&verifierv1.Config{
		VerifyCredentialSvc: verifyCredentialSvc,
		ProfileSvc:          verifierProfileSvc,
		KMSRegistry:         kmsRegistry,
		DocumentLoader:      documentLoader,
		VDR:                 conf.VDR,
		OIDCVPService:       oidc4vpService,
		Metrics:             metrics,
		Tracer:              conf.Tracer,
	})

	verifierv1.RegisterHandlers(e, verifierController)

	didConfigSvc := didconfiguration.New(&didconfiguration.Config{
		VerifierProfileService: verifierProfileSvc,
		IssuerProfileService:   issuerProfileSvc,
		Crypto:                 vcCrypto,
		KmsRegistry:            kmsRegistry,
		ExternalURL:            conf.StartupParameters.hostURLExternal,
	})

	if conf.StartupParameters.devMode {
		_ = devapi.NewController(&devapi.Config{
			DidConfigService:          didConfigSvc,
			RequestObjectStoreService: requestObjectStoreService,
		}, e)
	}

	_ = logapi.NewController(e)

	metricsProvider, err := NewMetricsProvider(conf.StartupParameters, internalEchoServer)
	if err != nil {
		return nil, err
	}

	if metricsProvider != nil {
		err = metricsProvider.Create()
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

type requestObjectStore interface {
	Create(ctx context.Context, request requestobject.RequestObject) (*requestobject.RequestObject, error)
	Find(ctx context.Context, id string) (*requestobject.RequestObject, error)
	Delete(ctx context.Context, id string) error
	GetResourceURL(id string) string
}

type credentialOfferReferenceStore interface {
	Create(
		ctx context.Context,
		request *oidc4ci.CredentialOfferResponse,
	) (string, error)
	CreateJWT(
		ctx context.Context,
		credentialOfferJWT string,
	) (string, error)
}

func getOIDC4VPClaimsStore(
	transientDataStoreType string,
	redisClientNoTracing *redis.Client,
	mongoClientNoTracing *mongodb.Client,
	oidc4vpReceivedClaimsDataTTL int32) (oidc4vp.TxClaimsStore, error) {
	var store oidc4vp.TxClaimsStore
	var err error

	switch transientDataStoreType {
	case redisStore:
		store = oidc4vpclaimsstoreredis.New(redisClientNoTracing, oidc4vpReceivedClaimsDataTTL)
		logger.Info("OIDC4VP claim data store Redis is used")
	default:
		store, err = oidc4vpclaimsstoremongo.New(
			context.Background(), mongoClientNoTracing, oidc4vpReceivedClaimsDataTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate Mongo store: %w", err)
		}

		logger.Info("OIDC4VP claim data store Mongo is used")
	}

	return store, nil
}

func getOIDC4VPTxStore(
	transientDataStoreType string,
	redisClient *redis.Client,
	mongodbClient *mongodb.Client,
	documentLoader jsonld.DocumentLoader,
	oidc4vpTransactionDataTTLSec int32) (oidc4vp.TxStoreStore, error) {
	var store oidc4vp.TxStoreStore
	var err error

	switch transientDataStoreType {
	case redisStore:
		store = oidc4vptxstoreredis.NewTxStore(
			redisClient, documentLoader, oidc4vpTransactionDataTTLSec)
		logger.Info("OIDC4VP tx store Redis is used")
	default:
		store, err = oidc4vptxstoremongo.NewTxStore(
			context.Background(),
			mongodbClient,
			documentLoader,
			oidc4vpTransactionDataTTLSec)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate Mongo store: %w", err)
		}

		logger.Info("OIDC4VP tx store Mongo is used")
	}

	return store, nil
}

func getOIDC4CIAuthStateStore(
	transientDataStoreType string,
	redisClient *redis.Client,
	mongodbClient *mongodb.Client,
	oidc4ciAuthStateTTL int32) (oidc4civ1.StateStore, error) {
	var store oidc4civ1.StateStore
	var err error

	switch transientDataStoreType {
	case redisStore:
		store = oidc4cistatestoreredis.New(redisClient, oidc4ciAuthStateTTL)
		logger.Info("OIDC4CI auth state store Redis is used")
	default:
		store, err = oidc4cistatestoremongo.New(context.Background(), mongodbClient, oidc4ciAuthStateTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate new OIDC4CI Mongo state store: %w", err)
		}

		logger.Info("OIDC4CI auth state store Mongo is used")
	}

	return store, nil
}

func getOIDC4VPNonceStore(
	transientDataStoreType string,
	redisClient *redis.Client,
	mongoClient *mongodb.Client,
	oidc4vpNonceStoreTTL int32) (oidc4vp.TxNonceStore, error) {
	var store oidc4vp.TxNonceStore
	var err error
	switch transientDataStoreType {
	case redisStore:
		store = oidc4vpnoncestoreredis.New(redisClient, oidc4vpNonceStoreTTL)
		logger.Info("OIDC nonce store Redis is used")
	default:
		store, err = oidc4vpnoncestoremongo.New(mongoClient, oidc4vpNonceStoreTTL)
		if err != nil {
			return nil, err
		}

		logger.Info("OIDC nonce store Mongo is used")
	}

	return store, nil
}

func getOIDC4CIClaimDataStore(
	transientDataStoreType string,
	redisClient *redis.Client,
	mongoClient *mongodb.Client,
	claimDataTTL int32) (oidc4ci.ClaimDataStore, error) {
	var store oidc4ci.ClaimDataStore
	var err error
	switch transientDataStoreType {
	case redisStore:
		store = oidc4ciclaimdatastoreredis.New(redisClient, claimDataTTL)
		logger.Info("claim data store Redis is used")
	default:
		store, err = claimdatastoremongo.New(context.Background(), mongoClient, claimDataTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate claim data store: %w", err)
		}

		logger.Info("claim data store Mongo is used")
	}

	return store, nil
}

func getOIDC4CITransactionStore(
	transientDataStoreType string,
	redisClient *redis.Client,
	mongoClient *mongodb.Client,
	oidc4ciTransactionDataTTL int32) (oidc4ci.TransactionStore, error) {
	var store oidc4ci.TransactionStore
	var err error
	switch transientDataStoreType {
	case redisStore:
		store = oidc4cinoncestoreredis.New(redisClient, oidc4ciTransactionDataTTL)
		logger.Info("OIDC4CI transaction store Redis is used")
	default:
		store, err = oidc4cinoncestoremongo.New(context.Background(), mongoClient, oidc4ciTransactionDataTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate oidc4ci store: %w", err)
		}

		logger.Info("OIDC4CI transaction store Mongo is used")
	}

	return store, nil
}

func createRequestObjectStore(
	repoType string,
	s3Region string,
	s3Bucket string,
	s3HostName string,
	mongoDbClient *mongodb.Client,
	isTraceEnabled bool,
) (requestObjectStore, error) {
	switch strings.ToLower(repoType) {
	case "s3":
		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(s3Region))
		if err != nil {
			return nil, err
		}

		if isTraceEnabled {
			otelaws.AppendMiddlewares(&cfg.APIOptions, otelaws.WithTracerProvider(otel.GetTracerProvider()))
		}

		return requestobjectstore2.NewStore(s3.NewFromConfig(cfg), s3Bucket, s3Region, s3HostName), nil
	default:
		return requestobjectstore.NewStore(mongoDbClient), nil
	}
}

func createCredentialOfferStore(
	s3Region string,
	s3Bucket string,
	s3HostName string,
	isTraceEnabled bool,
) (credentialOfferReferenceStore, error) {
	if s3Region == "" || s3Bucket == "" {
		return nil, nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(s3Region))
	if err != nil {
		return nil, err
	}

	if isTraceEnabled {
		otelaws.AppendMiddlewares(&cfg.APIOptions, otelaws.WithTracerProvider(otel.GetTracerProvider()))
	}

	return credentialoffer.NewStore(s3.NewFromConfig(cfg), s3Bucket, s3Region, s3HostName), nil
}

func createCredentialStatusListStores(
	repoType string,
	s3Region string,
	s3Bucket string,
	hostName string,
	mongoDbClient *mongodb.Client,
	isTraceEnabled bool,
) (credentialstatustypes.CSLVCStore, credentialstatustypes.CSLIndexStore, error) {
	cslIndexMongo := cslindexstore.NewStore(mongoDbClient)

	switch strings.ToLower(repoType) {
	case "s3":
		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(s3Region))
		if err != nil {
			return nil, nil, err
		}

		if isTraceEnabled {
			otelaws.AppendMiddlewares(&cfg.APIOptions, otelaws.WithTracerProvider(otel.GetTracerProvider()))
		}

		cslS3Store := cslstores3.NewStore(s3.NewFromConfig(cfg), s3Bucket, s3Region, hostName)

		return cslS3Store, cslIndexMongo, nil
	default:
		return cslvcstore.NewStore(mongoDbClient), cslIndexMongo, nil
	}
}

func newHTTPClient(tlsConfig *tls.Config, params *startupParameters,
	metrics metricsProvider.Metrics, id metricsProvider.ClientID) *http.Client {
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   params.httpParameters.dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          2000,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if params.tracingParams.exporter != tracing.None {
		transport = otelhttp.NewTransport(transport)
	}

	return &http.Client{
		Timeout:   params.httpParameters.timeout,
		Transport: metrics.InstrumentHTTPTransport(id, transport),
	}
}

func NewMetrics(parameters *startupParameters, e *echo.Echo, options startOpts) (metricsProvider.Metrics, error) {
	switch parameters.metricsProviderName {
	case "prometheus":
		cfg := echoprometheus.DefaultConfig
		cfg.Namespace = metricsProvider.Namespace
		cfg.Subsystem = metricsProvider.HTTPServer
		cfg.Scope = metricsProvider.HTTPServer
		cfg.Domain = "vcs"
		cfg.Version = options.version
		e.Use(echoprometheus.MetricsMiddlewareWithConfig(cfg))

		return promMetricsProvider.GetMetrics(cfg.Version, cfg.Domain, cfg.Scope), nil
	default:
		return noopMetricsProvider.GetMetrics(), nil
	}
}

func NewMetricsProvider(
	parameters *startupParameters,
	internalEchoServer *echo.Echo,
) (metricsProvider.Provider, error) {
	switch parameters.metricsProviderName {
	case "prometheus":
		provider := promMetricsProvider.NewPrometheusProvider(internalEchoServer)

		return provider, nil
	default:
		return nil, nil
	}
}

func buildOptions(opts ...StartOpts) startOpts {
	o := &startOpts{}

	for _, opt := range opts {
		opt(o)
	}

	return *o
}

func startServer(conf *Configuration, opts ...StartOpts) error {
	o := buildOptions(opts...)

	if o.server == nil {
		o.server = &http.Server{
			Addr:    conf.StartupParameters.hostURL,
			Handler: h2c.NewHandler(o.handler, &http2.Server{}),
		}
	}

	logger.Info("Starting vc-rest server on host", log.WithURL(conf.StartupParameters.hostURL))

	if conf.StartupParameters.tlsParameters.serveKeyPath != "" &&
		conf.StartupParameters.tlsParameters.serveCertPath != "" {
		return o.server.ListenAndServeTLS(conf.StartupParameters.tlsParameters.serveCertPath,
			conf.StartupParameters.tlsParameters.serveKeyPath)
	}

	return o.server.ListenAndServe()
}

func validateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, token string) bool {
	actHdr := r.Header.Get("Authorization")
	expHdr := "Bearer " + token

	if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

		return false
	}

	return true
}

func getOAuth2Clients(path string) ([]oauth2client.Client, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var clients []oauth2client.Client

	if err = json.NewDecoder(f).Decode(&clients); err != nil {
		return nil, err
	}

	return clients, nil
}

func createJSONLDDocumentLoader(mongoClient *mongodb.Client, tlsConfig *tls.Config,
	providerURLs []string, contextEnableRemote bool) (jsonld.DocumentLoader, error) {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("create ristretto cache: %w", err)
	}

	ldStore, err := ld.NewStoreProvider(mongoClient, cache)
	if err != nil {
		return nil, err
	}

	var loaderOpts []documentloader.Opts

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, url := range providerURLs {
		loaderOpts = append(loaderOpts,
			documentloader.WithRemoteProvider(
				remote.NewProvider(url, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	if contextEnableRemote {
		loaderOpts = append(loaderOpts,
			documentloader.WithRemoteDocumentLoader(jsonld.NewDefaultDocumentLoader(http.DefaultClient)))
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, err
	}

	return loader, nil
}
