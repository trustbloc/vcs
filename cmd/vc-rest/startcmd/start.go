/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/tink/go/subtle/random"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	"github.com/trustbloc/edge-core/pkg/utils/retry"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edv/pkg/client/edv"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"

	restholder "github.com/trustbloc/edge-service/pkg/restapi/holder"
	holderops "github.com/trustbloc/edge-service/pkg/restapi/holder/operation"
	restissuer "github.com/trustbloc/edge-service/pkg/restapi/issuer"
	issuerops "github.com/trustbloc/edge-service/pkg/restapi/issuer/operation"
	restverifier "github.com/trustbloc/edge-service/pkg/restapi/verifier"
	verifierops "github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "VC_REST_HOST_URL"

	edvURLFlagName      = "edv-url"
	edvURLFlagShorthand = "e"
	edvURLFlagUsage     = "URL EDV instance is running on. Format: HostName:Port."
	edvURLEnvKey        = "EDV_REST_HOST_URL"

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
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "l"
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
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + kmsSecretsDatabaseTypeEnvKey

	kmsSecretsDatabaseURLFlagName      = "kms-secrets-database-url" //nolint: gosec
	kmsSecretsDatabaseURLEnvKey        = "KMSSECRETS_DATABASE_URL"  //nolint: gosec
	kmsSecretsDatabaseURLFlagShorthand = "s"
	kmsSecretsDatabaseURLFlagUsage     = "The URL of the database. Not needed if using memstore. For CouchDB, " +
		"include the username:password@ text if required. It's recommended to not use the same database as the one " +
		"set in the " + databaseURLFlagName + " flag (or the " + databaseURLEnvKey + " env var) since having access " +
		"to the KMS secrets may allow the host of the provider to decrypt EDV encrypted documents. " +
		commonEnvVarUsageText + databaseURLEnvKey

	kmsSecretsDatabasePrefixFlagName  = "kms-secrets-database-prefix" //nolint: gosec
	kmsSecretsDatabasePrefixEnvKey    = "KMSSECRETS_DATABASE_PREFIX"  //nolint: gosec
	kmsSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving " +
		"the underlying KMS secrets database. " + commonEnvVarUsageText + kmsSecretsDatabasePrefixEnvKey

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set. " + commonEnvVarUsageText + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "VC_REST_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." + commonEnvVarUsageText + tlsCACertsEnvKey
	tlsCACertsEnvKey    = "VC_REST_TLS_CACERTS"

	maxRetriesFlagName      = "max-retries"
	maxRetriesEnvKey        = "MAX-RETRIES"
	maxRetriesFlagShorthand = "a"
	maxRetriesFlagUsage     = "If no VC is found when attempting to retrieve a VC from the EDV, this is the maximum " +
		"number of times to retry retrieval. Defaults to 5 if not set. " + commonEnvVarUsageText + maxRetriesEnvKey
	maxRetriesDefault = 5

	initialBackoffMillisecFlagName      = "initial-backoff-millisec"
	initialBackoffMillisecEnvKey        = "INITIAL_BACKOFF_MILLISEC"
	initialBackoffMillisecFlagShorthand = "i"
	initialBackoffMillisecFlagUsage     = "If no VC is found when attempting to retrieve a VC from the EDV, " +
		"this is the time to wait (in milliseconds) before the first retry attempt. " +
		commonEnvVarUsageText + initialBackoffMillisecEnvKey
	initialBackoffMillisecDefault = 250

	backoffFactorFlagName      = "backoff-factor"
	backoffFactorEnvKey        = "BACKOFF-FACTOR"
	backoffFactorFlagShorthand = "f"
	backoffFactorFlagUsage     = "If no VC is found when attempting to retrieve a VC from the EDV, this is the " +
		"factor to increase the time to wait for subsequent retries after the first. " +
		commonEnvVarUsageText + backoffFactorEnvKey
	backoffFactorDefault = 1.5

	tokenFlagName  = "api-token"
	tokenEnvKey    = "VC_REST_API_TOKEN" //nolint: gosec
	tokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		commonEnvVarUsageText + tokenEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "VC_REST_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		commonEnvVarUsageText + requestTokensEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"

	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodWeb     = "web"
	didMethodKey     = "key"
	didMethodFactom  = "factom"

	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName
)

var logger = log.New("vc-rest")

var errNegativeBackoffFactor = errors.New("the backoff factor cannot be negative")

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
	edvURL               string
	blocDomain           string
	hostURLExternal      string
	universalResolverURL string
	mode                 string
	dbParameters         *dbParameters
	retryParameters      *retry.Params
	tlsSystemCertPool    bool
	tlsCACerts           []string
	token                string
	requestTokens        map[string]string
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
		Long:  "Start vc-rest inside the edge-service",
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

	edvURL, err := cmdutils.GetUserSetVarFromString(cmd, edvURLFlagName, edvURLEnvKey, false)
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

	retryParams, err := getRetryParameters(cmd)
	if err != nil {
		return nil, err
	}

	token, err := cmdutils.GetUserSetVarFromString(cmd, tokenFlagName,
		tokenEnvKey, true)
	if err != nil {
		return nil, err
	}

	requestTokens, err := getRequestTokens(cmd)
	if err != nil {
		return nil, err
	}

	return &vcRestParameters{
		hostURL:              hostURL,
		edvURL:               edvURL,
		blocDomain:           blocDomain,
		hostURLExternal:      hostURLExternal,
		universalResolverURL: universalResolverURL,
		mode:                 mode,
		dbParameters:         dbParams,
		retryParameters:      retryParams,
		tlsSystemCertPool:    tlsSystemCertPool,
		tlsCACerts:           tlsCACerts,
		token:                token,
		requestTokens:        requestTokens,
	}, nil
}

func getRequestTokens(cmd *cobra.Command) (map[string]string, error) {
	requestTokens, err := cmdutils.GetUserSetVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey, true)
	if err != nil {
		return nil, err
	}

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case 2:
			tokens[split[0]] = split[1]
		default:
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens, nil
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

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey, true)
	if err != nil {
		return false, nil, err
	}

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

func getRetryParameters(cmd *cobra.Command) (*retry.Params, error) {
	maxRetries, err := getMaxRetries(cmd)
	if err != nil {
		return nil, err
	}

	initialBackoff, err := getInitialBackoff(cmd)
	if err != nil {
		return nil, err
	}

	backoffFactor, err := getBackoffFactor(cmd)
	if err != nil {
		return nil, err
	}

	return &retry.Params{
		MaxRetries:     uint(maxRetries),
		InitialBackoff: initialBackoff,
		BackoffFactor:  backoffFactor,
	}, nil
}

func getMaxRetries(cmd *cobra.Command) (uint64, error) {
	maxRetriesString, err := cmdutils.GetUserSetVarFromString(cmd, maxRetriesFlagName,
		maxRetriesEnvKey, true)
	if err != nil {
		return 0, err
	}

	var maxRetries uint64

	if maxRetriesString == "" {
		maxRetries = maxRetriesDefault
		logger.Infof("Max retries value not specified. The default value of " +
			strconv.Itoa(maxRetriesDefault) + " will be used.")
	} else {
		maxRetries, err = strconv.ParseUint(maxRetriesString, 10, 64)
		if err != nil {
			return 0, fmt.Errorf(`the given max retries value "%s" is not a valid non-negative integer: %w`,
				maxRetriesString, err)
		}
	}

	return maxRetries, nil
}

func getInitialBackoff(cmd *cobra.Command) (time.Duration, error) {
	initialBackoffMillisecString, err := cmdutils.GetUserSetVarFromString(cmd, initialBackoffMillisecFlagName,
		initialBackoffMillisecEnvKey, true)
	if err != nil {
		return 0, err
	}

	var initialBackoffMillisec uint64

	if initialBackoffMillisecString == "" {
		initialBackoffMillisec = initialBackoffMillisecDefault
		logger.Infof("Initial backoff value not specified. The default value of " +
			strconv.Itoa(initialBackoffMillisecDefault) + " will be used.")
	} else {
		initialBackoffMillisec, err = strconv.ParseUint(initialBackoffMillisecString, 10, 64)
		if err != nil {
			return 0, fmt.Errorf(`the given initial backoff value "%s" is not a valid non-negative integer: %w`,
				initialBackoffMillisecString, err)
		}
	}

	initialBackoff := time.Duration(initialBackoffMillisec) * time.Millisecond

	return initialBackoff, nil
}

func getBackoffFactor(cmd *cobra.Command) (float64, error) {
	backoffFactorString, err := cmdutils.GetUserSetVarFromString(cmd, backoffFactorFlagName,
		backoffFactorEnvKey, true)
	if err != nil {
		return 0, err
	}

	var backoffFactor float64

	if backoffFactorString == "" {
		backoffFactor = backoffFactorDefault
		logger.Infof("Backoff factor value not specified. The default value of " +
			fmt.Sprintf("%.1f", backoffFactorDefault) + " will be used.")
	} else {
		backoffFactor, err = strconv.ParseFloat(backoffFactorString, 64)
		if err != nil {
			return 0, fmt.Errorf(`the given backoff factor "%s" is not a valid floating point number: %w`,
				backoffFactorString, err)
		}

		if backoffFactor < 0 {
			return 0, errNegativeBackoffFactor
		}
	}

	return backoffFactor, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(edvURLFlagName, edvURLFlagShorthand, "", edvURLFlagUsage)
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
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(maxRetriesFlagName, maxRetriesFlagShorthand, "", maxRetriesFlagUsage)
	startCmd.Flags().StringP(initialBackoffMillisecFlagName, initialBackoffMillisecFlagShorthand, "",
		initialBackoffMillisecFlagUsage)
	startCmd.Flags().StringP(backoffFactorFlagName, backoffFactorFlagShorthand, "", backoffFactorFlagUsage)
	startCmd.Flags().StringP(tokenFlagName, "", "", tokenFlagUsage)
	startCmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
}

// nolint: gocyclo,funlen
func startEdgeService(parameters *vcRestParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	edgeServiceProvs, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	localKMS, err := createKMS(edgeServiceProvs)
	if err != nil {
		return err
	}

	// Create VDRI
	vdri, err := createVDRI(parameters.universalResolverURL, &tls.Config{RootCAs: rootCAs})
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

	issuerService, err := restissuer.New(&issuerops.Config{StoreProvider: edgeServiceProvs.provider,
		KMSSecretsProvider: edgeServiceProvs.kmsSecretsProvider,
		EDVClient:          edv.New(parameters.edvURL, edv.WithTLSConfig(&tls.Config{RootCAs: rootCAs})),
		KeyManager:         localKMS,
		Crypto:             crypto,
		VDRI:               vdri,
		HostURL:            externalHostURL,
		Domain:             parameters.blocDomain,
		TLSConfig:          &tls.Config{RootCAs: rootCAs},
		RetryParameters:    parameters.retryParameters})
	if err != nil {
		return err
	}

	holderService, err := restholder.New(&holderops.Config{TLSConfig: &tls.Config{RootCAs: rootCAs},
		StoreProvider: edgeServiceProvs.provider, KeyManager: localKMS, Crypto: crypto,
		VDRI: vdri, Domain: parameters.blocDomain})
	if err != nil {
		return err
	}

	verifierService, err := restverifier.New(&verifierops.Config{StoreProvider: edgeServiceProvs.provider,
		TLSConfig: &tls.Config{RootCAs: rootCAs}, VDRI: vdri, RequestTokens: parameters.requestTokens})
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

func createVDRI(universalResolver string, tlsConfig *tls.Config) (vdriapi.Registry, error) {
	var opts []vdripkg.Option

	var blocVDRIOpts []trustbloc.Option

	if universalResolver != "" {
		universalResolverVDRI, err := httpbinding.New(universalResolver,
			httpbinding.WithAccept(acceptsDID), httpbinding.WithTLSConfig(tlsConfig))
		if err != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", err)
		}

		// add universal resolver vdri
		opts = append(opts, vdripkg.WithVDRI(universalResolverVDRI))

		// add universal resolver to bloc vdri
		blocVDRIOpts = append(blocVDRIOpts, trustbloc.WithResolverURL(universalResolver),
			trustbloc.WithTLSConfig(tlsConfig))
	}

	// add bloc vdri
	opts = append(opts, vdripkg.WithVDRI(trustbloc.New(blocVDRIOpts...)))

	vdriProvider, err := context.New(context.WithLegacyKMS(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create new vdri provider: %w", err)
	}

	return vdripkg.New(vdriProvider, opts...), nil
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
		method == didMethodWeb || method == didMethodKey || method == didMethodFactom
}

type edgeServiceProviders struct {
	provider           storage.Provider
	kmsSecretsProvider ariesstorage.Provider
}

func createStoreProviders(parameters *vcRestParameters) (*edgeServiceProviders, error) {
	var edgeServiceProvs edgeServiceProviders

	checkForSameDBParams(parameters.dbParameters)

	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		edgeServiceProvs.provider = memstore.NewProvider()
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		var err error

		edgeServiceProvs.provider, err =
			couchdbstore.NewProvider(parameters.dbParameters.databaseURL,
				couchdbstore.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return &edgeServiceProviders{}, err
		}
	default:
		return &edgeServiceProviders{}, fmt.Errorf("database type not set to a valid type." +
			" run start --help to see the available options")
	}

	switch {
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMemOption):
		edgeServiceProvs.kmsSecretsProvider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeCouchDBOption):
		var err error

		edgeServiceProvs.kmsSecretsProvider, err =
			ariescouchdbstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
		if err != nil {
			return &edgeServiceProviders{}, err
		}

	default:
		return &edgeServiceProviders{}, fmt.Errorf("key database type not set to a valid type." +
			" run start --help to see the available options")
	}

	return &edgeServiceProvs, nil
}

func checkForSameDBParams(dbParams *dbParameters) {
	if strings.EqualFold(dbParams.databaseType, dbParams.kmsSecretsDatabaseType) &&
		strings.EqualFold(dbParams.databaseURL, dbParams.kmsSecretsDatabaseURL) {
		logger.Warnf("Database and KMS secrets database both set to the same provider. It's recommended to use a " +
			"separate provider for storage of KMS secrets to ensure that the provider hosting the EDVs " +
			"cannot read the stored encrypted documents.")
	}
}

func createKMS(edgeServiceProvs *edgeServiceProviders) (*localkms.LocalKMS, error) {
	localKMS, err := createLocalKMS(edgeServiceProvs.kmsSecretsProvider)
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
			masterKeyRaw := random.GetRandomBytes(uint32(32))
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

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodHead},
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
