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
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	oapimw "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/dgraph-io/ristretto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/trustbloc/vcs/component/otp"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/pkg/observability/tracing"
	"github.com/trustbloc/vcs/pkg/restapi/v1/version"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/claimdatastore"
	"github.com/trustbloc/vcs/pkg/storage/s3/credentialoffer"
	requestobjectstore2 "github.com/trustbloc/vcs/pkg/storage/s3/requestobjectstore"

	echoPrometheus "github.com/globocom/echo-prometheus"

	"github.com/trustbloc/vcs/api/spec"
	"github.com/trustbloc/vcs/component/credentialstatus"
	"github.com/trustbloc/vcs/component/event"
	"github.com/trustbloc/vcs/component/oidc/fositemongo"
	"github.com/trustbloc/vcs/component/oidc/vp"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	metricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
	promMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/prometheus"
	profilereader "github.com/trustbloc/vcs/pkg/profile/reader"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/devapi"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/logapi"
	"github.com/trustbloc/vcs/pkg/restapi/v1/mw"
	oidc4civ1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	oidc4vpv1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vp"
	verifierv1 "github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	credentialstatustypes "github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
	"github.com/trustbloc/vcs/pkg/service/wellknown"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	cslstoremongodb "github.com/trustbloc/vcs/pkg/storage/mongodb/cslstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4cistatestore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4cistore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vpclaimsstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vptxstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidcnoncestore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/requestobjectstore"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/vcstatusstore"
	cslstores3 "github.com/trustbloc/vcs/pkg/storage/s3/cslstore"
)

const (
	healthCheckEndpoint             = "/healthcheck"
	oidc4VPCheckEndpoint            = "/oidc/present"
	defaultGracefulShutdownDuration = 1 * time.Second
	cslSize                         = 10000
	devApiRequestObjectEndpoint     = "/request-object/:uuid"
	devApiDidConfigEndpoint         = "/:profileType/profiles/:profileID/well-known/did-config"
	logLevelsEndpoint               = "/loglevels"
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

			conf, err := prepareConfiguration(params)
			if err != nil {
				return fmt.Errorf("failed to prepare configuration: %w", err)
			}

			traceParams := params.tracingParams

			stopTracingProvider, _, err := tracing.Initialize(traceParams.provider, traceParams.serviceName, traceParams.collectorURL)
			if err != nil {
				return fmt.Errorf("initialize tracing: %w", err)
			}
			defer stopTracingProvider()

			internalEchoAddress := conf.StartupParameters.prometheusMetricsProviderParams.url
			internalEcho, ready := buildInternalEcho()
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

	e.HTTPErrorHandler = resterr.HTTPErrorHandler

	// Middlewares
	e.Use(echomw.Logger())
	e.Use(echomw.Recover())
	e.Use(echomw.CORS())

	return e
}

func buildInternalEcho() (*echo.Echo, *readiness) {
	e := echo.New()
	e.HideBanner = true
	e.Use(echomw.Recover())
	e.GET(healthCheckEndpoint, func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
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
	e.Use(echomw.Gzip())

	metrics, err := NewMetrics(conf.StartupParameters, e)
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
		Skipper: func(c echo.Context) bool {
			if c.Path() == devApiRequestObjectEndpoint || c.Path() == devApiDidConfigEndpoint {
				return true
			}
			if c.Path() == versionEndpoint || c.Path() == versionSystemEndpoint {
				return true
			}

			if c.Path() == logLevelsEndpoint {
				return true
			}

			return echomw.DefaultSkipper(c)
		},
	}))

	version.NewController(e, version.Config{
		Version:       options.version,
		ServerVersion: options.serverVersion,
	})

	if conf.StartupParameters.tracingParams.provider != "" {
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

	mongodbClient, err := mongodb.New(conf.StartupParameters.dbParameters.databaseURL,
		conf.StartupParameters.dbParameters.databasePrefix+"vcs_db",
		15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client: %w", err)
	}

	documentLoader, err := createJSONLDDocumentLoader(mongodbClient, tlsConfig,
		conf.StartupParameters.contextProviderURLs, conf.StartupParameters.contextEnableRemote)
	if err != nil {
		return nil, err
	}

	// Create event service
	eventSvc, err := event.Initialize(event.Config{
		TLSConfig: tlsConfig,
		CMD:       cmd,
	})
	if err != nil {
		return nil, err
	}

	getHTTPClient := func(id metricsProvider.ClientID) *http.Client {
		return newHTTPClient(tlsConfig, conf.StartupParameters, metrics, id)
	}

	// Issuer Profile Management API
	issuerProfileSvc, err := profilereader.NewIssuerReader(&profilereader.Config{
		TLSConfig:   tlsConfig,
		KMSRegistry: kmsRegistry,
		CMD:         cmd,
		HTTPClient:  getHTTPClient(metricsProvider.ClientIssuerProfile),
	})
	if err != nil {
		return nil, err
	}

	vcCrypto := crypto.New(conf.VDR, documentLoader)

	cslStore, err := createCredentialStatusListStore(
		conf.StartupParameters.cslStoreType,
		conf.StartupParameters.cslStoreS3Region,
		conf.StartupParameters.cslStoreS3Bucket,
		conf.StartupParameters.cslStoreS3HostName,
		mongodbClient)
	if err != nil {
		return nil, err
	}

	statusListVCSvc, err := credentialstatus.New(&credentialstatus.Config{
		VDR:            conf.VDR,
		HTTPClient:     getHTTPClient(metricsProvider.ClientCredentialStatus),
		RequestTokens:  conf.StartupParameters.requestTokens,
		DocumentLoader: documentLoader,
		CSLStore:       cslStore,
		VCStatusStore:  vcstatusstore.NewStore(mongodbClient),
		ListSize:       cslSize,
		ProfileService: issuerProfileSvc,
		KMSRegistry:    kmsRegistry,
		Crypto:         vcCrypto,
		CMD:            cmd,
		ExternalURL:    conf.StartupParameters.hostURLExternal,
	})
	if err != nil {
		return nil, err
	}

	issueCredentialSvc := issuecredential.New(&issuecredential.Config{
		VCStatusManager: statusListVCSvc,
		Crypto:          vcCrypto,
		KMSRegistry:     kmsRegistry,
	})

	oidc4ciStore, err := oidc4cistore.New(context.Background(), mongodbClient)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate oidc4ci store: %w", err)
	}

	claimDataStore, err := claimdatastore.New(context.Background(), mongodbClient, conf.StartupParameters.claimDataTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate claim data store: %w", err)
	}

	credentialOfferStore, err := createCredentialOfferStore( // credentialOfferStore is optional, so it can be nil
		conf.StartupParameters.credentialOfferRepositoryS3Region,
		conf.StartupParameters.credentialOfferRepositoryS3Bucket,
		conf.StartupParameters.credentialOfferRepositoryS3HostName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate credentialOfferStore: %w", err)
	}

	oidc4ciService, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore:              oidc4ciStore,
		ClaimDataStore:                claimDataStore,
		IssuerVCSPublicHost:           conf.StartupParameters.apiGatewayURL,
		WellKnownService:              wellknown.NewService(getHTTPClient(metricsProvider.ClientWellKnown)),
		ProfileService:                issuerProfileSvc,
		OAuth2Client:                  oauth2client.NewOAuth2Client(),
		HTTPClient:                    getHTTPClient(metricsProvider.ClientOIDC4CI),
		EventService:                  eventSvc,
		PinGenerator:                  otp.NewPinGenerator(),
		PreAuthCodeTTL:                conf.StartupParameters.claimDataTTL,
		EventTopic:                    conf.StartupParameters.issuerEventTopic,
		CredentialOfferReferenceStore: credentialOfferStore,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new oidc4ci service: %w", err)
	}

	oidc4ciStateStore, err := oidc4cistatestore.New(context.Background(), mongodbClient)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new oidc4ci state store: %w", err)
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

	var oauth2Clients []fositemongo.Client

	if conf.StartupParameters.oAuthClientsFilePath != "" {
		if oauth2Clients, err = getOAuth2Clients(conf.StartupParameters.oAuthClientsFilePath); err != nil {
			return nil, fmt.Errorf("failed to get oauth clients: %w", err)
		}
	}

	provider, err := bootstrapOAuthProvider(
		context.Background(),
		conf.StartupParameters.oAuthSecret,
		mongodbClient,
		oauth2Clients,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new oauth provider: %w", err)
	}

	oidc4civ1.RegisterHandlers(e, oidc4civ1.NewController(&oidc4civ1.Config{
		OAuth2Provider:          provider,
		StateStore:              oidc4ciStateStore,
		IssuerInteractionClient: issuerInteractionClient,
		IssuerVCSPublicHost:     conf.StartupParameters.apiGatewayURL, // use api gateway here, as this endpoint will be called by clients
		DefaultHTTPClient:       getHTTPClient(metricsProvider.ClientOIDC4CIV1),
		OAuth2Client:            oauth2client.NewOAuth2Client(),
		ExternalHostURL:         conf.StartupParameters.hostURLExternal, // use host external as this url will be called internally
		PreAuthorizeClient: func() *http.Client {
			client := getHTTPClient(metricsProvider.ClientPreAuth)
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			return client
		}(),
		JWTVerifier: jwt.NewVerifier(jwt.KeyResolverFunc(verifiable.NewVDRKeyResolver(conf.VDR).PublicKeyFetcher())),
	}))

	oidc4vpv1.RegisterHandlers(e, oidc4vpv1.NewController(&oidc4vpv1.Config{
		DefaultHTTPClient: getHTTPClient(metricsProvider.ClientOIDC4PV1),
		ExternalHostURL:   conf.StartupParameters.hostURLExternal, // use host external as this url will be called internally
	}))

	issuerv1.RegisterHandlers(e, issuerv1.NewController(&issuerv1.Config{
		EventSvc:               eventSvc,
		ProfileSvc:             issuerProfileSvc,
		KMSRegistry:            kmsRegistry,
		DocumentLoader:         documentLoader,
		IssueCredentialService: issueCredentialSvc,
		VcStatusManager:        statusListVCSvc,
		OIDC4CIService:         oidc4ciService,
		ExternalHostURL:        conf.StartupParameters.apiGatewayURL,
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

	verifyCredentialSvc := verifycredential.New(&verifycredential.Config{
		VCStatusProcessorGetter: statustype.GetVCStatusProcessor,
		StatusListVCResolver:    statusListVCSvc,
		DocumentLoader:          documentLoader,
		VDR:                     conf.VDR,
	})
	verifyPresentationSvc := verifypresentation.New(&verifypresentation.Config{
		VcVerifier:     verifyCredentialSvc,
		DocumentLoader: documentLoader,
		VDR:            conf.VDR,
	})
	oidc4vpTxStore := oidc4vptxstore.NewTxStore(mongodbClient, documentLoader)

	oidc4vpClaimsStore, err := oidc4vpclaimsstore.New(context.Background(), mongodbClient, documentLoader, conf.StartupParameters.vpReceivedClaimsDataTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate claim data store: %w", err)
	}

	oidcNonceStore, err := oidcnoncestore.New(mongodbClient)
	if err != nil {
		return nil, err
	}

	requestObjStore, err := createRequestObjectStore(
		conf.StartupParameters.requestObjectRepositoryType,
		conf.StartupParameters.requestObjectRepositoryS3Region,
		conf.StartupParameters.requestObjectRepositoryS3Bucket,
		conf.StartupParameters.requestObjectRepositoryS3HostName,
		mongodbClient,
	)
	if err != nil {
		return nil, err
	}

	// TODO: add parameter to specify live time of interaction request object
	requestObjStoreEndpoint := conf.StartupParameters.apiGatewayURL + "/request-object/"
	oidc4vpTxManager := oidc4vp.NewTxManager(oidcNonceStore, oidc4vpTxStore, oidc4vpClaimsStore, 15*time.Minute)

	requestObjectStoreService := vp.NewRequestObjectStore(requestObjStore, eventSvc,
		requestObjStoreEndpoint, conf.StartupParameters.verifierEventTopic)

	oidc4vpService := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:                 eventSvc,
		EventTopic:               conf.StartupParameters.verifierEventTopic,
		TransactionManager:       oidc4vpTxManager,
		RequestObjectPublicStore: requestObjectStoreService,
		KMSRegistry:              kmsRegistry,
		PublicKeyFetcher:         verifiable.NewVDRKeyResolver(conf.VDR).PublicKeyFetcher(),
		DocumentLoader:           documentLoader,
		ProfileService:           verifierProfileSvc,
		PresentationVerifier:     verifyPresentationSvc,
		RedirectURL:              conf.StartupParameters.apiGatewayURL + oidc4VPCheckEndpoint,
		TokenLifetime:            15 * time.Minute,
		Metrics:                  metrics,
	})
	verifierController := verifierv1.NewController(&verifierv1.Config{
		VerifyCredentialSvc: verifyCredentialSvc,
		ProfileSvc:          verifierProfileSvc,
		KMSRegistry:         kmsRegistry,
		DocumentLoader:      documentLoader,
		VDR:                 conf.VDR,
		OIDCVPService:       oidc4vpService,
		Metrics:             metrics,
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
}

func createRequestObjectStore(
	repoType string,
	s3Region string,
	s3Bucket string,
	s3HostName string,
	mongoDbClient *mongodb.Client,
) (requestObjectStore, error) {
	switch strings.ToLower(repoType) {
	case "s3":
		ses, err := session.NewSession(&aws.Config{Region: aws.String(s3Region)})
		if err != nil {
			return nil, err
		}

		return requestobjectstore2.NewStore(s3.New(ses), s3Bucket, s3Region, s3HostName), nil
	default:
		return requestobjectstore.NewStore(mongoDbClient), nil
	}
}

func createCredentialOfferStore(
	s3Region string,
	s3Bucket string,
	s3HostName string,
) (credentialOfferReferenceStore, error) {
	if s3Region == "" || s3Bucket == "" {
		return nil, nil
	}

	ses, err := session.NewSession(&aws.Config{Region: aws.String(s3Region)})
	if err != nil {
		return nil, err
	}

	return credentialoffer.NewStore(s3.New(ses), s3Bucket, s3Region, s3HostName), nil
}

func createCredentialStatusListStore(
	repoType string,
	s3Region string,
	s3Bucket string,
	hostName string,
	mongoDbClient *mongodb.Client,
) (credentialstatustypes.CSLStore, error) {
	cslStoreMongo := cslstoremongodb.NewStore(mongoDbClient)

	switch strings.ToLower(repoType) {
	case "s3":
		ses, err := session.NewSession(&aws.Config{Region: aws.String(s3Region)})
		if err != nil {
			return nil, err
		}

		return cslstores3.NewStore(s3.New(ses), cslStoreMongo, s3Bucket, s3Region, hostName), nil
	default:
		return cslStoreMongo, nil
	}
}

func newHTTPClient(tlsConfig *tls.Config, params *startupParameters,
	metrics metricsProvider.Metrics, id metricsProvider.ClientID) *http.Client {
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if params.tracingParams.provider != tracing.ProviderNone {
		transport = otelhttp.NewTransport(transport)
	}

	return &http.Client{
		Timeout:   time.Minute,
		Transport: metrics.InstrumentHTTPTransport(id, transport),
	}
}

func NewMetrics(parameters *startupParameters, e *echo.Echo) (metricsProvider.Metrics, error) {
	switch parameters.metricsProviderName {
	case "prometheus":
		cfg := echoPrometheus.DefaultConfig
		cfg.Namespace = metricsProvider.Namespace
		cfg.Subsystem = metricsProvider.HTTPServer

		e.Use(echoPrometheus.MetricsMiddlewareWithConfig(cfg))
		return promMetricsProvider.GetMetrics(), nil
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
			Handler: o.handler,
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

func getOAuth2Clients(path string) ([]fositemongo.Client, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var clients []fositemongo.Client

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
