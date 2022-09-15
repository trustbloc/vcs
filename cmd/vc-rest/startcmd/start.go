/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"

	"github.com/google/tink/go/subtle/random"
	"github.com/gorilla/mux"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesmysqlstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	restlogspec "github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/vcs/cmd/common"
	"github.com/trustbloc/vcs/pkg/ld"
	restholder "github.com/trustbloc/vcs/pkg/restapi/holder"
	holderops "github.com/trustbloc/vcs/pkg/restapi/holder/operation"
	restissuer "github.com/trustbloc/vcs/pkg/restapi/issuer"
	issuerops "github.com/trustbloc/vcs/pkg/restapi/issuer/operation"
	restverifier "github.com/trustbloc/vcs/pkg/restapi/verifier"
	verifierops "github.com/trustbloc/vcs/pkg/restapi/verifier/operation"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "VC_REST_HOST_URL"

	blocDomainFlagName      = "bloc-domain"
	blocDomainFlagShorthand = "b"
	blocDomainFlagUsage     = "Bloc domain"
	blocDomainEnvKey        = "BLOC_DOMAIN"

	hostURLExternalFlagName      = "host-url-external"
	hostURLExternalFlagShorthand = "x"
	hostURLExternalEnvKey        = "VC_REST_HOST_URL_EXTERNAL"
	hostURLExternalFlagUsage     = "Host External Name:Port This is the URL for the host server as seen externally." +
		" If not provided, then the host url will be used here. " + commonEnvVarUsageText + hostURLExternalEnvKey

	universalResolverURLFlagName      = "universal-resolver-url"
	universalResolverURLFlagShorthand = "r"
	universalResolverURLFlagUsage     = "Universal Resolver instance is running on. Format: HostName:Port."
	universalResolverURLEnvKey        = "UNIVERSAL_RESOLVER_HOST_URL"

	modeFlagName      = "mode"
	modeFlagShorthand = "m"
	modeFlagUsage     = "Mode in which the vc-rest service will run. Possible values: " +
		"['issuer', 'verifier', 'holder', 'combined'] (default: combined)."
	modeEnvKey = "VC_REST_MODE"

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "DATABASE_TYPE"
	databaseTypeFlagShorthand = "t"
	databaseTypeFlagUsage     = "The type of database to use for everything except key storage. " +
		"Supported options: mem, couchdb, mysql, mongodb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "v"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	// Linter gosec flags these as "potential hardcoded credentials". They are not, hence the nolint annotations.
	kmsSecretsDatabaseTypeFlagName      = "kms-secrets-database-type" //nolint: gosec
	kmsSecretsDatabaseTypeEnvKey        = "KMSSECRETS_DATABASE_TYPE"  //nolint: gosec
	kmsSecretsDatabaseTypeFlagShorthand = "k"
	kmsSecretsDatabaseTypeFlagUsage     = "The type of database to use for storage of KMS secrets. " +
		"Supported options: mem, couchdb, mysql, mongodb. " + commonEnvVarUsageText + kmsSecretsDatabaseTypeEnvKey

	kmsSecretsDatabaseURLFlagName      = "kms-secrets-database-url" //nolint: gosec
	kmsSecretsDatabaseURLEnvKey        = "KMSSECRETS_DATABASE_URL"  //nolint: gosec
	kmsSecretsDatabaseURLFlagShorthand = "s"
	kmsSecretsDatabaseURLFlagUsage     = "The URL of the database. Not needed if using memstore. For CouchDB, " +
		"include the username:password@ text if required. " +
		commonEnvVarUsageText + databaseURLEnvKey

	kmsSecretsDatabasePrefixFlagName  = "kms-secrets-database-prefix" //nolint: gosec
	kmsSecretsDatabasePrefixEnvKey    = "KMSSECRETS_DATABASE_PREFIX"  //nolint: gosec
	kmsSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving " +
		"the underlying KMS secrets database. " + commonEnvVarUsageText + kmsSecretsDatabasePrefixEnvKey

	// remote JSON-LD context provider url flag.
	contextProviderFlagName  = "context-provider-url"
	contextProviderEnvKey    = "VC_REST_CONTEXT_PROVIDER_URL"
	contextProviderFlagUsage = "Remote context provider URL to get JSON-LD contexts from." +
		" This flag can be repeated, allowing setting up multiple context providers." +
		commonEnvVarUsageText + contextProviderEnvKey

	// enable fetching JSON-LD contexts from the network.
	contextEnableRemoteFlagName  = "context-enable-remote"
	contextEnableRemoteEnvKey    = "VC_REST_CONTEXT_ENABLE_REMOTE"
	contextEnableRemoteFlagUsage = "Enables remote JSON-LD contexts fetching. Defaults to false." +
		commonEnvVarUsageText + contextEnableRemoteEnvKey

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set. " + commonEnvVarUsageText + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "VC_REST_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." + commonEnvVarUsageText + tlsCACertsEnvKey
	tlsCACertsEnvKey    = "VC_REST_TLS_CACERTS"

	tokenFlagName  = "api-token"
	tokenEnvKey    = "VC_REST_API_TOKEN" //nolint: gosec
	tokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		commonEnvVarUsageText + tokenEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "VC_REST_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		commonEnvVarUsageText + requestTokensEnvKey

	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "VC_REST_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "DID anchor origin" + commonEnvVarUsageText + didAnchorOriginEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMYSQLDBOption = "mysql"
	databaseTypeMongoDBOption = "mongodb"

	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodFactom  = "factom"

	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	splitRequestTokenLength = 2
	masterKeyNumBytes       = 32
)

var logger = log.New("vc-rest")

// mode in which to run the vc-rest service
type mode string

const (
	verifier mode = "verifier"
	issuer   mode = "issuer"
	holder   mode = "holder"
	combined mode = "combined"

	// api
	healthCheckEndpoint = "/healthcheck"
)

type vcRestParameters struct {
	hostURL              string
	blocDomain           string
	hostURLExternal      string
	universalResolverURL string
	mode                 string
	dbParameters         *dbParameters
	tlsSystemCertPool    bool
	tlsCACerts           []string
	token                string
	requestTokens        map[string]string
	logLevel             string
	didAnchorOrigin      string
	contextProviderURLs  []string
	contextEnableRemote  bool
}

type dbParameters struct {
	databaseType             string
	databaseURL              string
	databasePrefix           string
	kmsSecretsDatabaseType   string
	kmsSecretsDatabaseURL    string
	kmsSecretsDatabasePrefix string
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start vc-rest",
		Long:  "Start vc-rest inside the vcs",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getVCRestParameters(cmd)
			if err != nil {
				return err
			}

			return startEdgeService(parameters, srv)
		},
	}
}

// nolint: gocyclo,funlen
func getVCRestParameters(cmd *cobra.Command) (*vcRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	blocDomain, err := cmdutils.GetUserSetVarFromString(cmd, blocDomainFlagName, blocDomainEnvKey, false)
	if err != nil {
		return nil, err
	}

	hostURLExternal, err := cmdutils.GetUserSetVarFromString(cmd, hostURLExternalFlagName,
		hostURLExternalEnvKey, true)
	if err != nil {
		return nil, err
	}

	universalResolverURL, err := cmdutils.GetUserSetVarFromString(cmd, universalResolverURLFlagName,
		universalResolverURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	mode, err := getMode(cmd)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := getDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	token, err := cmdutils.GetUserSetVarFromString(cmd, tokenFlagName,
		tokenEnvKey, true)
	if err != nil {
		return nil, err
	}

	requestTokens := getRequestTokens(cmd)

	loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	didAnchorOrigin := cmdutils.GetUserSetOptionalVarFromString(cmd, didAnchorOriginFlagName, didAnchorOriginEnvKey)

	contextProviderURLs := cmdutils.GetUserSetOptionalCSVVar(cmd, contextProviderFlagName,
		contextProviderEnvKey)

	contextEnableRemoteConfig, err := cmdutils.GetUserSetVarFromString(cmd, contextEnableRemoteFlagName,
		contextEnableRemoteEnvKey, true)
	if err != nil {
		return nil, err
	}

	contextEnableRemote := false

	if contextEnableRemoteConfig != "" {
		contextEnableRemote, err = strconv.ParseBool(contextEnableRemoteConfig)
		if err != nil {
			return nil, err
		}
	}

	return &vcRestParameters{
		hostURL: hostURL,

		blocDomain:           blocDomain,
		hostURLExternal:      hostURLExternal,
		universalResolverURL: universalResolverURL,
		mode:                 mode,
		dbParameters:         dbParams,
		tlsSystemCertPool:    tlsSystemCertPool,
		tlsCACerts:           tlsCACerts,
		token:                token,
		requestTokens:        requestTokens,
		logLevel:             loggingLevel,
		didAnchorOrigin:      didAnchorOrigin,
		contextProviderURLs:  contextProviderURLs,
		contextEnableRemote:  contextEnableRemote,
	}, nil
}

func getRequestTokens(cmd *cobra.Command) map[string]string {
	requestTokens := cmdutils.GetUserSetOptionalCSVVar(cmd, requestTokensFlagName,
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

func getMode(cmd *cobra.Command) (string, error) {
	mode, err := cmdutils.GetUserSetVarFromString(cmd, modeFlagName, modeEnvKey, true)
	if err != nil {
		return "", err
	}

	if !supportedMode(mode) {
		return "nil", fmt.Errorf("unsupported mode: %s", mode)
	}

	if mode == "" {
		mode = string(combined)
	}

	return mode, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalCSVVar(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	return tlsSystemCertPool, tlsCACerts, nil
}

func getDBParameters(cmd *cobra.Command) (*dbParameters, error) {
	databaseType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName,
		databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	databaseURL, err := cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName,
		databaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName,
		databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyDatabaseType, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabaseTypeFlagName,
		kmsSecretsDatabaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	keyDatabaseURL, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabaseURLFlagName,
		kmsSecretsDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyDatabasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabasePrefixFlagName,
		kmsSecretsDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &dbParameters{
		databaseType:             databaseType,
		databaseURL:              databaseURL,
		databasePrefix:           databasePrefix,
		kmsSecretsDatabaseType:   keyDatabaseType,
		kmsSecretsDatabaseURL:    keyDatabaseURL,
		kmsSecretsDatabasePrefix: keyDatabasePrefix,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(blocDomainFlagName, blocDomainFlagShorthand, "", blocDomainFlagUsage)
	startCmd.Flags().StringP(hostURLExternalFlagName, hostURLExternalFlagShorthand, "", hostURLExternalFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, modeFlagShorthand, "", modeFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseTypeFlagName, kmsSecretsDatabaseTypeFlagShorthand, "",
		kmsSecretsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseURLFlagName, kmsSecretsDatabaseURLFlagShorthand, "",
		kmsSecretsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabasePrefixFlagName, "", "", kmsSecretsDatabasePrefixFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringSliceP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tokenFlagName, "", "", tokenFlagUsage)
	startCmd.Flags().StringSliceP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
	startCmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
	startCmd.Flags().StringSliceP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
	startCmd.Flags().StringP(contextEnableRemoteFlagName, "", "", contextEnableRemoteFlagUsage)
}

// nolint: gocyclo,funlen,gocognit
func startEdgeService(parameters *vcRestParameters, srv server) error {
	if parameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, parameters.logLevel)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	edgeServiceProvs, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	localKMS, err := createKMS(edgeServiceProvs.kmsSecretsProvider)
	if err != nil {
		return err
	}

	// Create VDRI
	vdr, err := createVDRI(parameters.universalResolverURL,
		&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, parameters.blocDomain,
		parameters.requestTokens["sidetreeToken"])
	if err != nil {
		return err
	}

	externalHostURL := parameters.hostURL
	if parameters.hostURLExternal != "" {
		externalHostURL = parameters.hostURLExternal
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	if parameters.token != "" {
		router.Use(authorizationMiddleware(parameters.token))
	}

	ldStore, err := ld.NewStoreProvider(edgeServiceProvs.provider)
	if err != nil {
		return err
	}

	loader, err := createJSONLDDocumentLoader(ldStore, rootCAs, parameters.contextProviderURLs,
		parameters.contextEnableRemote)
	if err != nil {
		return err
	}

	issuerService, err := restissuer.New(&issuerops.Config{
		StoreProvider:      edgeServiceProvs.provider,
		KMSSecretsProvider: edgeServiceProvs.kmsSecretsProvider,
		KeyManager:         localKMS,
		Crypto:             crypto,
		VDRI:               vdr,
		HostURL:            externalHostURL,
		Domain:             parameters.blocDomain,
		TLSConfig:          &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		DIDAnchorOrigin:    parameters.didAnchorOrigin,
		DocumentLoader:     loader,
	})
	if err != nil {
		return err
	}

	holderService, err := restholder.New(&holderops.Config{
		TLSConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		},
		StoreProvider: edgeServiceProvs.provider, KeyManager: localKMS, Crypto: crypto,
		VDRI: vdr, Domain: parameters.blocDomain,
		DIDAnchorOrigin: parameters.didAnchorOrigin,
		DocumentLoader:  loader,
	})
	if err != nil {
		return err
	}

	verifierService, err := restverifier.New(&verifierops.Config{
		StoreProvider: edgeServiceProvs.provider,
		TLSConfig:     &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, VDRI: vdr,
		RequestTokens:  parameters.requestTokens,
		DocumentLoader: loader,
	})
	if err != nil {
		return err
	}

	if parameters.mode == string(issuer) || parameters.mode == string(combined) {
		for _, handler := range issuerService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	if parameters.mode == string(verifier) || parameters.mode == string(combined) {
		for _, handler := range verifierService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	if parameters.mode == string(holder) || parameters.mode == string(combined) {
		for _, handler := range holderService.GetOperations() {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	for _, handler := range restlogspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// handlers for JSON-LD context operations
	for _, handler := range ldrest.New(ldsvc.New(ldStore)).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	logger.Infof("Starting vc rest server on host %s", parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

type kmsProvider struct {
	storageProvider   ariesstorage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
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

	opts = append(opts, vdrpkg.WithVDR(vdr), vdrpkg.WithVDR(key.New()), vdrpkg.WithVDR(&webVDR{
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			}},
		VDR: web.New(),
	}))

	return vdrpkg.New(opts...), nil
}

func supportedMode(mode string) bool {
	if len(mode) > 0 && mode != string(verifier) && mode != string(issuer) && mode != string(holder) {
		return false
	}

	return true
}

// acceptsDID returns if given did method is accepted by VC REST api
func acceptsDID(method string) bool {
	return method == didMethodVeres || method == didMethodElement || method == didMethodSov ||
		method == didMethodFactom
}

type edgeServiceProviders struct {
	provider           ariesstorage.Provider
	kmsSecretsProvider ariesstorage.Provider
}

func createStoreProviders(parameters *vcRestParameters) (*edgeServiceProviders, error) {
	var edgeServiceProvs edgeServiceProviders

	var err error

	edgeServiceProvs.provider, err = createMainStoreProvider(parameters)
	if err != nil {
		return nil, err
	}

	edgeServiceProvs.kmsSecretsProvider, err = createKMSSecretsProvider(parameters)
	if err != nil {
		return nil, err
	}

	return &edgeServiceProvs, nil
}

func createMainStoreProvider(parameters *vcRestParameters) (ariesstorage.Provider, error) { //nolint: dupl
	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		return ariesmemstorage.NewProvider(), nil
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		return ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMYSQLDBOption):
		return ariesmysqlstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		return ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
	default:
		return nil, fmt.Errorf("%s is not a valid database type."+
			" run start --help to see the available options", parameters.dbParameters.databaseType)
	}
}

func createKMSSecretsProvider(parameters *vcRestParameters) (ariesstorage.Provider, error) { //nolint: dupl
	switch {
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMemOption):
		return ariesmemstorage.NewProvider(), nil
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeCouchDBOption):
		return ariescouchdbstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMYSQLDBOption):
		return ariesmysqlstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
			ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMongoDBOption):
		return ariesmongodbstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
	default:
		return nil, fmt.Errorf("%s is not a valid KMS secrets database type."+
			" run start --help to see the available options", parameters.dbParameters.kmsSecretsDatabaseType)
	}
}

func createKMS(kmsSecretsProvider ariesstorage.Provider) (*localkms.LocalKMS, error) {
	localKMS, err := createLocalKMS(kmsSecretsProvider)
	if err != nil {
		return nil, err
	}

	return localKMS, nil
}

func createLocalKMS(kmsSecretsStoreProvider ariesstorage.Provider) (*localkms.LocalKMS, error) {
	masterKeyReader, err := prepareMasterKeyReader(kmsSecretsStoreProvider)
	if err != nil {
		return nil, err
	}

	secretLockService, err := local.NewService(masterKeyReader, nil)
	if err != nil {
		return nil, err
	}

	kmsProv := kmsProvider{
		storageProvider:   kmsSecretsStoreProvider,
		secretLockService: secretLockService,
	}

	return localkms.New(masterKeyURI, kmsProv)
}

// prepareMasterKeyReader prepares a master key reader for secret lock usage
func prepareMasterKeyReader(kmsSecretsStoreProvider ariesstorage.Provider) (*bytes.Reader, error) {
	masterKeyStore, err := kmsSecretsStoreProvider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			masterKeyRaw := random.GetRandomBytes(uint32(masterKeyNumBytes))
			masterKey = []byte(base64.URLEncoding.EncodeToString(masterKeyRaw))

			putErr := masterKeyStore.Put(masterKeyDBKeyName, masterKey)
			if putErr != nil {
				return nil, putErr
			}
		} else {
			return nil, err
		}
	}

	masterKeyReader := bytes.NewReader(masterKey)

	return masterKeyReader, nil
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

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
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
