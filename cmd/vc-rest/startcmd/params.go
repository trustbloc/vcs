/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/cmdutil-go/pkg/utils/cmd"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/cmd/common"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/observability/tracing"
	profilereader "github.com/trustbloc/vcs/pkg/profile/reader"
)

// kms params
const (
	kmsTypeFlagName  = "default-kms-type"
	kmsTypeEnvKey    = "VC_REST_DEFAULT_KMS_TYPE"
	kmsTypeFlagUsage = "Default KMS type (local,web,aws)." +
		" Alternatively, this can be set with the following environment variable: " + kmsTypeEnvKey

	kmsEndpointFlagName  = "default-kms-endpoint"
	kmsEndpointEnvKey    = "VC_REST_DEFAULT_KMS_ENDPOINT"
	kmsEndpointFlagUsage = "Default KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	kmsRegionFlagName  = "default-kms-region"
	kmsRegionEnvKey    = "VC_REST_DEFAULT_KMS_REGION"
	kmsRegionFlagUsage = "Default KMS region." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	secretLockKeyPathFlagName  = "default-kms-secret-lock-key-path"
	secretLockKeyPathEnvKey    = "VC_REST_DEFAULT_KMS_SECRET_LOCK_KEY_PATH"
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey

	aliasPrefixFlagName  = "default-kms-alias-prefix"
	aliasPrefixEnvKey    = "VC_REST_DEFAULT_KMS_ALIAS_PREFIX"
	aliasPrefixFlagUsage = "alias prefix" +
		commonEnvVarUsageText + aliasPrefixEnvKey

	// Linter gosec flags these as "potential hardcoded credentials". They are not, hence the nolint annotations.
	kmsSecretsDatabaseTypeFlagName      = "default-kms-secrets-database-type"         //nolint: gosec
	kmsSecretsDatabaseTypeEnvKey        = "VC_REST_DEFAULT_KMS_SECRETS_DATABASE_TYPE" //nolint: gosec
	kmsSecretsDatabaseTypeFlagShorthand = "k"
	kmsSecretsDatabaseTypeFlagUsage     = "The type of database to use for storage of KMS secrets. " +
		"Supported options: mem, mongodb. " + commonEnvVarUsageText + kmsSecretsDatabaseTypeEnvKey

	kmsSecretsDatabaseURLFlagName      = "default-kms-secrets-database-url"         //nolint: gosec
	kmsSecretsDatabaseURLEnvKey        = "VC_REST_DEFAULT_KMS_SECRETS_DATABASE_URL" //nolint: gosec
	kmsSecretsDatabaseURLFlagShorthand = "s"
	kmsSecretsDatabaseURLFlagUsage     = "The URL (or connection string) of the database. Not needed if using memstore. For mongodb, " +
		"include the mongodb://mongodb.example.com:27017. " +
		commonEnvVarUsageText + databaseURLEnvKey

	kmsSecretsDatabasePrefixFlagName  = "default=kms-secrets-database-prefix"         //nolint: gosec
	kmsSecretsDatabasePrefixEnvKey    = "VC_REST_DEFAULT_KMS_SECRETS_DATABASE_PREFIX" //nolint: gosec
	kmsSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving " +
		"the underlying KMS secrets database. " + commonEnvVarUsageText + kmsSecretsDatabasePrefixEnvKey
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "VC_REST_HOST_URL"

	apiGatewayURLFlagName      = "api-gateway-url"
	apiGatewayURLFlagShorthand = "g"
	apiGatewayURLFlagUsage     = "An optional API Gateteway (oathkeeper, etc). Format: http://<GATEWAY_HOST>:<PORT> ." +
		" If not provided, then the host url will be used here. " + commonEnvVarUsageText + hostURLExternalEnvKey
	apiGatewayURLEnvKey = "VC_REST_API_GATEWAY_URL"

	hostURLExternalFlagName      = "host-url-external"
	hostURLExternalFlagShorthand = "x"
	hostURLExternalEnvKey        = "VC_REST_HOST_URL_EXTERNAL"
	hostURLExternalFlagUsage     = "This is the URL for the host server as seen externally. Format: http://<HOST>:<PORT>"

	universalResolverURLFlagName      = "universal-resolver-url"
	universalResolverURLFlagShorthand = "r"
	universalResolverURLFlagUsage     = "Universal Resolver instance is running on. Format: HostName:Port."
	universalResolverURLEnvKey        = "UNIVERSAL_RESOLVER_HOST_URL"

	orbDomainFlagName  = "orb-domain"
	orbDomainFlagUsage = "Orb domain."
	orbDomainEnvKey    = "VC_REST_ORB_DOMAIN"

	modeFlagName      = "mode"
	modeFlagShorthand = "m"
	modeFlagUsage     = "Mode in which the vc-rest service will run. Possible values: " +
		"['issuer', 'verifier', 'holder', 'combined'] (default: combined)."
	modeEnvKey = "VC_REST_MODE"

	devModeFlagName      = "dev-mode"
	devModeFlagShorthand = "d"
	devModeFlagUsage     = "Developer mode expose some additional apis. Possible values: " +
		"true, false (default: false)"
	devModeEnvKey = "VC_REST_DEV_MODE"

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

	tlsCertificateFlagName  = "tls-certificate"
	tlsCertificateFlagUsage = "TLS certificate for vcs server. " + commonEnvVarUsageText + tlsCertificateLEnvKey
	tlsCertificateLEnvKey   = "VCS_REST_TLS_CERTIFICATE"

	tlsKeyFlagName  = "tls-key"
	tlsKeyFlagUsage = "TLS key for vcs server. " + commonEnvVarUsageText + tlsKeyEnvKey
	tlsKeyEnvKey    = "VC_REST_TLS_KEY"

	tokenFlagName  = "api-token"
	tokenEnvKey    = "VC_REST_API_TOKEN" //nolint: gosec
	tokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		commonEnvVarUsageText + tokenEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "VC_REST_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		commonEnvVarUsageText + requestTokensEnvKey

	oAuthSecretFlagName      = "oauth-secret"
	oAuthSecretFlagShorthand = "o"
	oAuthSecretFlagUsage     = "oauth global secret, any string. Example: secret-for-signing-and-verifying-signatures"
	oAuthSecretFlagEnvKey    = "VC_OAUTH_SECRET"

	oAuthClientsFilePathFlagName  = "oauth-client-file-path"
	oAuthClientsFilePathEnvKey    = "VC_OAUTH_CLIENTS_FILE_PATH"
	oAuthClientsFilePathFlagUsage = "Path to file with oauth clients. " +
		commonEnvVarUsageText + oAuthClientsFilePathEnvKey

	claimDataTTLFlagName  = "claim-data-ttl"
	claimDataTTLEnvKey    = "VC_CLAIM_DATA_TTL"
	claimDataTTLFlagUsage = "Claim data TTL in OIDC4VC pre-auth code flow. Defaults to 3600s. " +
		commonEnvVarUsageText + hostURLExternalEnvKey

	metricsProviderFlagName         = "metrics-provider-name"
	metricsProviderEnvKey           = "VC_METRICS_PROVIDER_NAME"
	allowedMetricsProviderFlagUsage = "The metrics provider name (for example: 'prometheus' etc.). " +
		commonEnvVarUsageText + metricsProviderEnvKey

	promHttpUrlFlagName             = "prom-http-url"
	promHttpUrlEnvKey               = "VC_PROM_HTTP_URL"
	allowedPromHttpUrlFlagNameUsage = "URL that exposes the prometheus metrics endpoint. Format: HostName:Port. "

	databaseTypeMongoDBOption = "mongodb"

	requestObjectRepositoryTypeFlagName  = "request-object-repository-type"
	requestObjectRepositoryTypeEnvKey    = "REQUEST_OBJECT_REPOSITORY_TYPE"
	requestObjectRepositoryTypeFlagUsage = "Repository type for request-object. Supported: mongodb,s3. Default: mongodb"

	requestObjectRepositoryS3BucketFlagName  = "request-object-repository-s3-bucket"
	requestObjectRepositoryS3BucketEnvKey    = "REQUEST_OBJECT_REPOSITORY_S3_BUCKET"
	requestObjectRepositoryS3BucketFlagUsage = "request-object S3 Bucket"

	requestObjectRepositoryS3RegionFlagName  = "request-object-repository-s3-region"
	requestObjectRepositoryS3RegionEnvKey    = "REQUEST_OBJECT_REPOSITORY_S3_REGION"
	requestObjectRepositoryS3RegionFlagUsage = "request-object S3 Region"

	requestObjectRepositoryS3HostNameFlagName  = "request-object-repository-s3-hostname"
	requestObjectRepositoryS3HostNameEnvKey    = "REQUEST_OBJECT_REPOSITORY_S3_HOSTNAME"
	requestObjectRepositoryS3HostNameFlagUsage = "request-object S3 Hostname"

	cslStoreTypeFlagName = "csl-store-type"
	cslStoreTypeEnvKey   = "CSL_STORE_TYPE"
	cslStoreFlagUsage    = "Store type for CSL (Credential Status List). Supported: mongodb,s3. Default: mongodb"

	cslStoreS3BucketFlagName  = "csl-store-s3-bucket"
	cslStoreS3BucketEnvKey    = "CSL_STORE_S3_BUCKET"
	cslStoreS3BucketFlagUsage = "CSL (Credential Status List) S3 Bucket"

	cslStoreS3RegionFlagName  = "csl-store-s3-region"
	cslStoreS3RegionEnvKey    = "CSL_STORE_S3_REGION"
	cslStoreS3RegionFlagUsage = "CSL (Credential Status List) S3 Region"

	cslStoreS3HostNameFlagName  = "csl-store-s3-hostname"
	cslStoreS3HostNameEnvKey    = "CSL_STORE_S3_HOSTNAME"
	cslStoreS3HostNameFlagUsage = "CSL (Credential Status List) S3 Hostname"

	issuerTopicFlagName  = "issuer-event-topic"
	issuerTopicEnvKey    = "VC_REST_ISSUER_EVENT_TOPIC"
	issuerTopicFlagUsage = "The name of the issuer event topic. " + commonEnvVarUsageText + issuerTopicEnvKey

	verifierTopicFlagName  = "verifier-event-topic"
	verifierTopicEnvKey    = "VC_REST_VERIFIER_EVENT_TOPIC"
	verifierTopicFlagUsage = "The name of the verifier event topic. " + commonEnvVarUsageText + verifierTopicEnvKey

	tracingProviderFlagName  = "tracing-provider"
	tracingProviderEnvKey    = "VC_REST_TRACING_PROVIDER"
	tracingProviderFlagUsage = "The tracing provider (for example, JAEGER). " +
		commonEnvVarUsageText + tracingProviderEnvKey

	tracingCollectorURLFlagName  = "tracing-collector-url"
	tracingCollectorURLEnvKey    = "VC_REST_TRACING_COLLECTOR_URL"
	tracingCollectorURLFlagUsage = "The URL of the tracing collector. " +
		commonEnvVarUsageText + tracingCollectorURLEnvKey

	tracingServiceNameFlagName  = "tracing-service-name"
	tracingServiceNameEnvKey    = "VC_REST_TRACING_SERVICE_NAME"
	tracingServiceNameFlagUsage = "The name of the tracing service. Default: vcs. " +
		commonEnvVarUsageText + tracingServiceNameEnvKey

	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodWeb     = "web"
	didMethodFactom  = "factom"
	didMethodORB     = "orb"
	didMethodKey     = "key"
	didMethodION     = "ion"

	splitRequestTokenLength = 2

	defaultTracingServiceName = "vcs"
)

const (
	defaultClaimDataTTL = 3600 * time.Second
)

type startupParameters struct {
	hostURL                           string
	hostURLExternal                   string
	universalResolverURL              string
	orbDomain                         string
	mode                              string
	dbParameters                      *dbParameters
	kmsParameters                     *kmsParameters
	token                             string
	requestTokens                     map[string]string
	logLevel                          string
	contextProviderURLs               []string
	contextEnableRemote               bool
	tlsParameters                     *tlsParameters
	devMode                           bool
	oAuthSecret                       string
	oAuthClientsFilePath              string
	metricsProviderName               string
	prometheusMetricsProviderParams   *prometheusMetricsProviderParams
	apiGatewayURL                     string
	requestObjectRepositoryType       string
	requestObjectRepositoryS3Bucket   string
	requestObjectRepositoryS3Region   string
	requestObjectRepositoryS3HostName string
	cslStoreType                      string
	cslStoreS3Bucket                  string
	cslStoreS3Region                  string
	cslStoreS3HostName                string
	issuerEventTopic                  string
	verifierEventTopic                string
	claimDataTTL                      int32
	tracingParams                     *tracingParams
}

type prometheusMetricsProviderParams struct {
	url string
}

type tracingParams struct {
	provider     tracing.ProviderType
	collectorURL string
	serviceName  string
}

type dbParameters struct {
	databaseType   string
	databaseURL    string
	databasePrefix string
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type kmsParameters struct {
	kmsType                  kms.Type
	kmsEndpoint              string
	kmsRegion                string
	kmsSecretsDatabaseType   string
	kmsSecretsDatabaseURL    string
	kmsSecretsDatabasePrefix string
	secretLockKeyPath        string
	aliasPrefix              string
}

// nolint: gocyclo,funlen
func getStartupParameters(cmd *cobra.Command) (*startupParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	hostURLExternal, err := cmdutils.GetUserSetVarFromString(cmd, hostURLExternalFlagName,
		hostURLExternalEnvKey, false)
	if err != nil {
		return nil, err
	}

	apiGatewayURL := cmdutils.GetUserSetOptionalVarFromString(cmd, apiGatewayURLFlagName, apiGatewayURLEnvKey)

	if len(apiGatewayURL) == 0 {
		apiGatewayURL = hostURLExternal
	}

	oAuthSecret, err := cmdutils.GetUserSetVarFromString(cmd, oAuthSecretFlagName, oAuthSecretFlagEnvKey, false)
	if err != nil {
		return nil, err
	}

	metricsProviderName, err := getMetricsProviderName(cmd)
	if err != nil {
		return nil, err
	}

	var prometheusMetricsProviderParams *prometheusMetricsProviderParams
	if metricsProviderName == "prometheus" {
		prometheusMetricsProviderParams, err = getPrometheusMetricsProviderParams(cmd)
	}
	if err != nil {
		return nil, err
	}

	universalResolverURL := cmdutils.GetUserSetOptionalVarFromString(cmd, universalResolverURLFlagName,
		universalResolverURLEnvKey)

	orbDomain := cmdutils.GetUserSetOptionalVarFromString(cmd, orbDomainFlagName, orbDomainEnvKey)

	mode, err := getMode(cmd)
	if err != nil {
		return nil, err
	}

	tlsParameters, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := getDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	kmsParams, err := getKMSParameters(cmd)
	if err != nil {
		return nil, err
	}

	token := cmdutils.GetUserSetOptionalVarFromString(cmd, tokenFlagName, tokenEnvKey)

	requestTokens := getRequestTokens(cmd)

	loggingLevel := cmdutils.GetUserSetOptionalVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey)

	contextProviderURLs := cmdutils.GetUserSetOptionalCSVVar(cmd, contextProviderFlagName,
		contextProviderEnvKey)

	contextEnableRemoteConfig := cmdutils.GetUserSetOptionalVarFromString(cmd, contextEnableRemoteFlagName,
		contextEnableRemoteEnvKey)

	devMode, err := getDevMode(cmd)
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

	oAuthClientsFilePath, err := cmdutils.GetUserSetVarFromString(cmd, oAuthClientsFilePathFlagName,
		oAuthClientsFilePathEnvKey, true)
	if err != nil {
		return nil, err
	}

	requestObjectRepositoryType := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		requestObjectRepositoryTypeFlagName,
		requestObjectRepositoryTypeEnvKey,
	)
	requestObjectRepositoryS3Bucket := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		requestObjectRepositoryS3BucketFlagName,
		requestObjectRepositoryS3BucketEnvKey,
	)
	requestObjectRepositoryS3Region := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		requestObjectRepositoryS3RegionFlagName,
		requestObjectRepositoryS3RegionEnvKey,
	)

	requestObjectRepositoryS3HostName := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		requestObjectRepositoryS3HostNameFlagName,
		requestObjectRepositoryS3HostNameEnvKey,
	)

	cslStoreType := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		cslStoreTypeFlagName,
		cslStoreTypeEnvKey,
	)
	cslStoreS3Bucket := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		cslStoreS3BucketFlagName,
		cslStoreS3BucketEnvKey,
	)
	cslStoreS3Region := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		cslStoreS3RegionFlagName,
		cslStoreS3RegionEnvKey,
	)

	cslStoreS3HostName := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		cslStoreS3HostNameFlagName,
		cslStoreS3HostNameEnvKey,
	)

	issuerTopic := cmdutils.GetUserSetOptionalVarFromString(cmd, issuerTopicFlagName, issuerTopicEnvKey)
	if issuerTopic == "" {
		issuerTopic = spi.IssuerEventTopic
	}

	verifierTopic := cmdutils.GetUserSetOptionalVarFromString(cmd, verifierTopicFlagName, verifierTopicEnvKey)
	if verifierTopic == "" {
		verifierTopic = spi.VerifierEventTopic
	}

	claimDataTTL, err := getDuration(cmd, claimDataTTLFlagName, claimDataTTLEnvKey, defaultClaimDataTTL)
	if err != nil {
		return nil, err
	}

	tracingParams, err := getTracingParams(cmd)
	if err != nil {
		return nil, err
	}

	return &startupParameters{
		hostURL:                           hostURL,
		hostURLExternal:                   hostURLExternal,
		universalResolverURL:              universalResolverURL,
		orbDomain:                         orbDomain,
		mode:                              mode,
		dbParameters:                      dbParams,
		kmsParameters:                     kmsParams,
		tlsParameters:                     tlsParameters,
		token:                             token,
		requestTokens:                     requestTokens,
		logLevel:                          loggingLevel,
		contextProviderURLs:               contextProviderURLs,
		contextEnableRemote:               contextEnableRemote,
		devMode:                           devMode,
		oAuthSecret:                       oAuthSecret,
		oAuthClientsFilePath:              oAuthClientsFilePath,
		metricsProviderName:               metricsProviderName,
		prometheusMetricsProviderParams:   prometheusMetricsProviderParams,
		apiGatewayURL:                     apiGatewayURL,
		requestObjectRepositoryType:       requestObjectRepositoryType,
		requestObjectRepositoryS3Bucket:   requestObjectRepositoryS3Bucket,
		requestObjectRepositoryS3Region:   requestObjectRepositoryS3Region,
		requestObjectRepositoryS3HostName: requestObjectRepositoryS3HostName,
		cslStoreType:                      cslStoreType,
		cslStoreS3Bucket:                  cslStoreS3Bucket,
		cslStoreS3Region:                  cslStoreS3Region,
		cslStoreS3HostName:                cslStoreS3HostName,
		issuerEventTopic:                  issuerTopic,
		verifierEventTopic:                verifierTopic,
		claimDataTTL:                      int32(claimDataTTL.Seconds()),
		tracingParams:                     tracingParams,
	}, nil
}

func getMetricsProviderName(cmd *cobra.Command) (string, error) {
	metricsProvider, err := cmdutils.GetUserSetVarFromString(cmd, metricsProviderFlagName, metricsProviderEnvKey, true)
	if err != nil {
		return "", err
	}

	return metricsProvider, nil
}

func getPrometheusMetricsProviderParams(cmd *cobra.Command) (*prometheusMetricsProviderParams, error) {
	promMetricsUrl, err := cmdutils.GetUserSetVarFromString(cmd, promHttpUrlFlagName, promHttpUrlEnvKey, false)
	if err != nil {
		return nil, err
	}

	return &prometheusMetricsProviderParams{url: promMetricsUrl}, nil
}

func getDevMode(cmd *cobra.Command) (bool, error) {
	mode, err := cmdutils.GetUserSetVarFromString(cmd, devModeFlagName, devModeEnvKey, true)
	if err != nil {
		return false, err
	}

	if len(mode) == 0 {
		return false, nil
	}

	return strconv.ParseBool(mode)
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

func supportedMode(mode string) bool {
	if len(mode) > 0 && mode != string(verifier) && mode != string(issuer) && mode != string(holder) {
		return false
	}

	return true
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

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsCertificateFlagName, tlsCertificateLEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsKeyFlagName, tlsKeyEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func getKMSParameters(cmd *cobra.Command) (*kmsParameters, error) {
	kmsTypeStr, err := cmdutils.GetUserSetVarFromString(cmd, kmsTypeFlagName, kmsTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	kmsType := kms.Type(kmsTypeStr)

	if !supportedKmsType(kmsType) {
		return nil, fmt.Errorf("unsupported kms type: %s", kmsType)
	}

	kmsEndpoint := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsEndpointFlagName, kmsEndpointEnvKey)

	kmsRegion := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsRegionFlagName, kmsRegionEnvKey)

	secretLockKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, secretLockKeyPathFlagName, secretLockKeyPathEnvKey)
	aliasPrefix := cmdutils.GetUserSetOptionalVarFromString(cmd, aliasPrefixFlagName, aliasPrefixEnvKey)

	keyDatabaseType, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabaseTypeFlagName,
		kmsSecretsDatabaseTypeEnvKey, kmsType != kms.Local)
	if err != nil {
		return nil, err
	}
	keyDatabaseURL := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsSecretsDatabaseURLFlagName,
		kmsSecretsDatabaseURLEnvKey)
	keyDatabasePrefix := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsSecretsDatabasePrefixFlagName,
		kmsSecretsDatabasePrefixEnvKey)

	return &kmsParameters{
		kmsType:                  kmsType,
		kmsEndpoint:              kmsEndpoint,
		kmsRegion:                kmsRegion,
		secretLockKeyPath:        secretLockKeyPath,
		kmsSecretsDatabaseType:   keyDatabaseType,
		kmsSecretsDatabaseURL:    keyDatabaseURL,
		kmsSecretsDatabasePrefix: keyDatabasePrefix,
		aliasPrefix:              aliasPrefix,
	}, nil
}

func supportedKmsType(kmsType kms.Type) bool {
	if kmsType != kms.Local && kmsType != kms.Web && kmsType != kms.AWS {
		return false
	}

	return true
}

func getDuration(cmd *cobra.Command, flagName, envKey string,
	defaultDuration time.Duration) (time.Duration, error) {
	timeoutStr, err := cmdutils.GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return -1, err
	}

	if timeoutStr == "" {
		return defaultDuration, nil
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return -1, fmt.Errorf("invalid value [%s]: %w", timeoutStr, err)
	}

	return timeout, nil
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

	return &dbParameters{
		databaseType:   databaseType,
		databaseURL:    databaseURL,
		databasePrefix: databasePrefix,
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
			logger.Warn("invalid token", log.WithToken(token))
		}
	}

	return tokens
}

func getTracingParams(cmd *cobra.Command) (*tracingParams, error) {
	serviceName := cmdutils.GetOptionalString(cmd, tracingServiceNameFlagName, tracingServiceNameEnvKey)
	if serviceName == "" {
		serviceName = defaultTracingServiceName
	}

	params := &tracingParams{
		provider:    cmdutils.GetOptionalString(cmd, tracingProviderFlagName, tracingProviderEnvKey),
		serviceName: serviceName,
	}

	switch params.provider {
	case tracing.ProviderNone:
		return params, nil
	case tracing.ProviderJaeger:
		var err error

		params.collectorURL, err = cmdutils.GetString(cmd, tracingCollectorURLFlagName, tracingCollectorURLEnvKey, false)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported tracing provider: %s", params.provider)
	}

	return params, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(apiGatewayURLFlagName, apiGatewayURLFlagShorthand, "", apiGatewayURLFlagUsage)
	startCmd.Flags().StringP(oAuthSecretFlagName, oAuthSecretFlagShorthand, "", oAuthSecretFlagUsage)
	startCmd.Flags().StringP(hostURLExternalFlagName, hostURLExternalFlagShorthand, "", hostURLExternalFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
	startCmd.Flags().StringP(orbDomainFlagName, "", "", orbDomainFlagUsage)
	startCmd.Flags().StringP(modeFlagName, modeFlagShorthand, "", modeFlagUsage)
	startCmd.Flags().StringP(devModeFlagName, devModeFlagShorthand, "", devModeFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringSliceP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tokenFlagName, "", "", tokenFlagUsage)
	startCmd.Flags().StringSliceP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
	startCmd.Flags().StringSliceP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
	startCmd.Flags().StringP(contextEnableRemoteFlagName, "", "", contextEnableRemoteFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseTypeFlagName, kmsSecretsDatabaseTypeFlagShorthand, "",
		kmsSecretsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseURLFlagName, kmsSecretsDatabaseURLFlagShorthand, "",
		kmsSecretsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabasePrefixFlagName, "", "", kmsSecretsDatabasePrefixFlagUsage)
	startCmd.Flags().String(kmsTypeFlagName, "", kmsTypeFlagUsage)
	startCmd.Flags().String(kmsEndpointFlagName, "", kmsEndpointFlagUsage)
	startCmd.Flags().String(secretLockKeyPathFlagName, "", secretLockKeyPathFlagUsage)
	startCmd.Flags().String(aliasPrefixFlagName, "", aliasPrefixFlagUsage)
	startCmd.Flags().String(kmsRegionFlagName, "", kmsRegionFlagUsage)
	startCmd.Flags().StringP(tlsCertificateFlagName, "", "", tlsCertificateFlagUsage)
	startCmd.Flags().StringP(tlsKeyFlagName, "", "", tlsKeyFlagUsage)
	startCmd.Flags().StringP(metricsProviderFlagName, "", "", allowedMetricsProviderFlagUsage)
	startCmd.Flags().StringP(promHttpUrlFlagName, "", "", allowedPromHttpUrlFlagNameUsage)
	startCmd.Flags().StringP(oAuthClientsFilePathFlagName, "", "", oAuthClientsFilePathFlagUsage)

	startCmd.Flags().String(requestObjectRepositoryTypeFlagName, "", requestObjectRepositoryTypeFlagUsage)
	startCmd.Flags().String(requestObjectRepositoryS3BucketFlagName, "", requestObjectRepositoryS3BucketFlagUsage)
	startCmd.Flags().String(requestObjectRepositoryS3RegionFlagName, "", requestObjectRepositoryS3RegionFlagUsage)
	startCmd.Flags().String(requestObjectRepositoryS3HostNameFlagName, "", requestObjectRepositoryS3HostNameFlagUsage)

	startCmd.Flags().String(cslStoreTypeFlagName, "", cslStoreFlagUsage)
	startCmd.Flags().String(cslStoreS3BucketFlagName, "", cslStoreS3BucketFlagUsage)
	startCmd.Flags().String(cslStoreS3RegionFlagName, "", cslStoreS3RegionFlagUsage)
	startCmd.Flags().String(cslStoreS3HostNameFlagName, "", cslStoreS3HostNameFlagUsage)

	startCmd.Flags().StringP(issuerTopicFlagName, "", "", issuerTopicFlagUsage)
	startCmd.Flags().StringP(verifierTopicFlagName, "", "", verifierTopicFlagUsage)
	startCmd.Flags().StringP(claimDataTTLFlagName, "", "", claimDataTTLFlagUsage)

	startCmd.Flags().StringP(tracingProviderFlagName, "", "", tracingProviderFlagUsage)
	startCmd.Flags().StringP(tracingCollectorURLFlagName, "", "", tracingCollectorURLFlagUsage)
	startCmd.Flags().StringP(tracingServiceNameFlagName, "", "", tracingServiceNameFlagUsage)

	profilereader.AddFlags(startCmd)
}
