/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/mux"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmysql "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/edge-service/pkg/ld"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/healthcheck"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the comparator instance on. Format: HostName:Port."
	hostURLEnvKey        = "COMPARATOR_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "COMPARATOR_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "COMPARATOR_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "COMPARATOR_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "COMPARATOR_TLS_SERVE_KEY"

	datasourceNameFlagName  = "dsn"
	datasourceNameFlagUsage = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, couchdb, mysql]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = "COMPARATOR_DSN"

	datasourceTimeoutFlagName  = "dsn-timeout"
	datasourceTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: " + datasourceTimeoutDefault + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + datasourceTimeoutEnvKey
	datasourceTimeoutEnvKey  = "COMPARATOR_DSN_TIMEOUT"
	datasourceTimeoutDefault = "30"

	databasePrefixFlagName  = "database-prefix"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey
	databasePrefixEnvKey = "COMPARATOR_DATABASE_PREFIX"

	didDomainFlagName  = "did-domain"
	didDomainFlagUsage = "URL to the did consortium's domain." +
		" Alternatively, this can be set with the following environment variable: " + didDomainEnvKey
	didDomainEnvKey = "COMPARATOR_DID_DOMAIN"

	cshURLFlagName  = "csh-url"
	cshURLFlagUsage = "URL for confidential storage hub." +
		" Alternatively, this can be set with the following environment variable: " + cshURLEnvKey
	cshURLEnvKey = "COMPARATOR_CSH_URL"

	vaultURLFlagName  = "vault-url"
	vaultURLFlagUsage = "URL for vault server." +
		" Alternatively, this can be set with the following environment variable: " + vaultURLEnvKey
	vaultURLEnvKey = "COMPARATOR_VAULT_URL"

	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "COMPARATOR_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "DID anchor origin." +
		" Alternatively, this can be set with the following environment variable: " + didAnchorOriginEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "COMPARATOR_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey

	splitRequestTokenLength = 2
)

const (
	keystorePrimaryKeyURI = "local-lock://keystorekms"
	sleep                 = 1 * time.Second
)

var logger = log.New("comparator-rest")

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	"couchdb": func(dsn, prefix string) (storage.Provider, error) {
		return ariescouchdbstorage.NewProvider(dsn, ariescouchdbstorage.WithDBPrefix(prefix))
	},
	"mysql": func(dsn, prefix string) (storage.Provider, error) {
		return ariesmysql.NewProvider(dsn, ariesmysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type dsnParams struct {
	dsn      string
	timeout  uint64
	dbPrefix string
}

type serviceParameters struct {
	host            string
	tlsParams       *tlsParameters
	dsnParams       *dsnParams
	didDomain       string
	cshURL          string
	vaultURL        string
	didAnchorOrigin string
	requestTokens   map[string]string
}

type server interface {
	ListenAndServe(host string, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile == "" || keyFile == "" {
		return http.ListenAndServe(host, router)
	}

	return http.ListenAndServeTLS(host, certFile, keyFile, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	cmd := createStartCmd(srv)

	createFlags(cmd)

	return cmd
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Starts a comparator server",
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := getParameters(cmd)
			if err != nil {
				return err
			}

			return startService(params, srv)
		},
	}
}

func getParameters(cmd *cobra.Command) (*serviceParameters, error) {
	host, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dsnParams, err := getDsnParams(cmd)
	if err != nil {
		return nil, err
	}

	didDomain, err := cmdutils.GetUserSetVarFromString(cmd, didDomainFlagName, didDomainEnvKey, false)
	if err != nil {
		return nil, err
	}

	cshURL, err := cmdutils.GetUserSetVarFromString(cmd, cshURLFlagName, cshURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	vaultURL, err := cmdutils.GetUserSetVarFromString(cmd, vaultURLFlagName, vaultURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	didAnchorOrigin := cmdutils.GetUserSetOptionalVarFromString(cmd, didAnchorOriginFlagName, didAnchorOriginEnvKey)

	requestTokens := getRequestTokens(cmd)

	return &serviceParameters{
		host:            host,
		tlsParams:       tlsParams,
		dsnParams:       dsnParams,
		didDomain:       didDomain,
		cshURL:          cshURL,
		vaultURL:        vaultURL,
		didAnchorOrigin: didAnchorOrigin,
		requestTokens:   requestTokens,
	}, err
}

func getDsnParams(cmd *cobra.Command) (*dsnParams, error) {
	params := &dsnParams{}

	var err error

	params.dsn, err = cmdutils.GetUserSetVarFromString(cmd, datasourceNameFlagName, datasourceNameEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dsn: %w", err)
	}

	timeout := cmdutils.GetUserSetOptionalVarFromString(cmd, datasourceTimeoutFlagName, datasourceTimeoutEnvKey)

	if timeout == "" {
		timeout = datasourceTimeoutDefault
	}

	t, err := strconv.Atoi(timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dsn timeout %s: %w", timeout, err)
	}

	params.timeout = uint64(t)

	params.dbPrefix = cmdutils.GetUserSetOptionalVarFromString(cmd, databasePrefixFlagName, databasePrefixEnvKey)

	return params, nil
}

func getRequestTokens(cmd *cobra.Command) map[string]string {
	requestTokens := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey)

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case splitRequestTokenLength:
			tokens[split[0]] = split[1]
		default:
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens
}

func initStore(dbURL string, timeout uint64, prefix string) (storage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, err
	}

	providerFunc, supported := supportedStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store storage.Provider

	err = retry(func() error {
		var openErr error
		store, openErr = providerFunc(dsn, prefix)
		return openErr
	}, timeout)
	if err != nil {
		return nil, fmt.Errorf("store init - failed to connect to storage at %s : %w", dsn, err)
	}

	return store, nil
}

func retry(fn func() error, timeout uint64) error {
	numRetries, err := strconv.Atoi(datasourceTimeoutDefault)
	if err != nil {
		return fmt.Errorf("failed to parse dsn timeout %d: %w", timeout, err)
	}

	if timeout != 0 {
		numRetries = int(timeout)
	}

	return backoff.RetryNotify(
		fn,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), uint64(numRetries)),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
}

func getDBParams(dbURL string) (driver, dsn string, err error) {
	const (
		urlParts = 2
	)

	parsed := strings.SplitN(dbURL, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", dbURL)
	}

	driver = parsed[0]
	dsn = strings.TrimPrefix(parsed[1], "//")

	return driver, dsn, nil
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	cmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	cmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
	cmd.Flags().StringP(datasourceNameFlagName, "", "", datasourceNameFlagUsage)
	cmd.Flags().StringP(datasourceTimeoutFlagName, "", "", datasourceTimeoutFlagUsage)
	cmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)
	cmd.Flags().StringP(didDomainFlagName, "", "", didDomainFlagUsage)
	cmd.Flags().StringP(cshURLFlagName, "", "", cshURLFlagUsage)
	cmd.Flags().StringP(vaultURLFlagName, "", "", vaultURLFlagUsage)
	cmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
	cmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
}

//nolint:funlen,gocyclo
func startService(params *serviceParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(params.tlsParams.systemCertPool, params.tlsParams.caCerts)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	storeProvider, err := initStore(params.dsnParams.dsn, params.dsnParams.timeout, params.dsnParams.dbPrefix)
	if err != nil {
		return err
	}

	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		storageProvider: storeProvider,
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return err
	}

	trustblocVDR, err := orb.New(nil, orb.WithDomain(params.didDomain), orb.WithTLSConfig(tlsConfig),
		orb.WithAuthToken(params.requestTokens["sidetreeToken"]))
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	ldStore, err := ld.NewStoreProvider(storeProvider)
	if err != nil {
		return err
	}

	loader, err := ld.NewDocumentLoader(ldStore)
	if err != nil {
		return err
	}

	service, err := comparator.New(&operation.Config{
		VDR:             vdr.New(vdr.WithVDR(trustblocVDR)),
		KeyManager:      keyManager,
		TLSConfig:       tlsConfig,
		DIDMethod:       orb.DIDMethod,
		StoreProvider:   storeProvider,
		CSHBaseURL:      params.cshURL,
		VaultBaseURL:    params.vaultURL,
		DIDDomain:       params.didDomain,
		DIDAnchorOrigin: params.didAnchorOrigin,
		DocumentLoader:  loader,
	})
	if err != nil {
		return err
	}

	for _, handler := range service.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range ldrest.New(ldsvc.New(ldStore)).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(params.host, params.tlsParams.serveCertPath, params.tlsParams.serveKeyPath,
		cors.New(cors.Options{
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodDelete,
			},
			AllowedHeaders: []string{
				"Origin",
				"Accept",
				"Content-Type",
				"X-Requested-With",
				"Authorization",
			},
		}).Handler(router))
}
