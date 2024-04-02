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
		"Supported options: mongodb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "v"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	redisURLFlagName  = "redis-url"
	redisURLEnvKey    = "VC_REDIS_URL"
	redisURLFlagUsage = "The list of comma-separated Redis URLs. " +
		"The type of the returned client depends on the following conditions: " +
		"1. If the " + redisSentinelMasterNameEnvKey + " is specified, a sentinel-backed FailoverClient is returned. " +
		"2. if the number of Addrs is two or more, a ClusterClient is returned. " +
		"3. Otherwise, a single-node Client is returned." + commonEnvVarUsageText + redisURLEnvKey

	redisSentinelMasterNameFlagName  = "redis-sentinel-master-name"
	redisSentinelMasterNameEnvKey    = "REDIS_SENTINEL_MASTER_NAME"
	redisSentinelMasterNameFlagUsage = "The sentinel master name." +
		commonEnvVarUsageText + redisSentinelMasterNameEnvKey

	redisAuthPasswordFlagName  = "vc-redis-password"
	redisAuthPasswordEnvKey    = "VC_REDIS_PASSWORD"
	redisAuthPasswordFlagUsage = "Redis auth password." +
		commonEnvVarUsageText + redisAuthPasswordEnvKey

	redisDisableTLSFlagName  = "vc-redis-disable-tls"
	redisDisableTLSEnvKey    = "VC_REDIS_DISABLE_TLS"
	redisDisableTLSFlagUsage = "Disable Redis TLS." + commonEnvVarUsageText + redisDisableTLSEnvKey

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

	httpTimeoutFlagName  = "http-timeout"
	httpTimeoutEnvKey    = "HTTP_TIMEOUT"
	httpTimeoutFlagUsage = "The timeout for http requests. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + httpTimeoutEnvKey

	httpDialTimeoutFlagName  = "http-dial-timeout"
	httpDialTimeoutEnvKey    = "HTTP_DIAL_TIMEOUT"
	httpDialTimeoutFlagUsage = "The timeout for http dial. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + httpDialTimeoutEnvKey

	httpForceAttemptHTTP2FlagName  = "http-force-attempt-http2"
	httpForceAttemptHTTP2EnvKey    = "HTTP_FORCE_ATTEMPT_HTTP2"
	httpForceAttemptHTTP2FlagUsage = "The force attempt HTTP2 flag for http dial. Default value is true" +
		commonEnvVarUsageText + httpForceAttemptHTTP2EnvKey

	tlsKeyFlagName  = "tls-key"
	tlsKeyFlagUsage = "TLS key for vcs server. " + commonEnvVarUsageText + tlsKeyEnvKey
	tlsKeyEnvKey    = "VC_REST_TLS_KEY"

	tokenFlagName  = "api-token"
	tokenEnvKey    = "VC_REST_API_TOKEN" //nolint: gosec
	tokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		commonEnvVarUsageText + tokenEnvKey

	dataEncryptionKeyIDFlagName  = "data-encryption-key-id"
	dataEncryptionKeyIDEnvKey    = "VC_REST_DATA_ENCRYPTION_KEY_ID" //nolint: gosec
	dataEncryptionKeyIDFlagUsage = "Data Encryption & Decryption KeyID. " +
		commonEnvVarUsageText + dataEncryptionKeyIDEnvKey

	dataEncryptionCompressionAlgorithmFlagName  = "data-encryption-compression-algorithm"
	dataEncryptionCompressionAlgorithmEnvKey    = "VC_REST_DATA_ENCRYPTION_COMPRESSION_ALGORITHM" //nolint: gosec
	dataEncryptionCompressionAlgorithmFlagUsage = "Data Encryption & Decryption Compression algorithm. Supported: none,gzip,zstd. Default: none. " +
		commonEnvVarUsageText + dataEncryptionCompressionAlgorithmEnvKey

	dataEncryptionKeyLengthFlagName  = "data-encryption-key-length"
	dataEncryptionKeyLengthEnvKey    = "VC_REST_DATA_ENCRYPTION_KEY_LENGTH" //nolint: gosec
	dataEncryptionKeyLengthFlagUsage = "Data Encryption & Decryption key length. " +
		"For AES - Default: 256" +
		commonEnvVarUsageText + dataEncryptionKeyLengthEnvKey

	dataEncryptionDisabledFlagName  = "data-encryption-disabled"
	dataEncryptionDisabledEnvKey    = "VC_REST_DATA_ENCRYPTION_DISABLED" //nolint: gosec
	dataEncryptionDisabledFlagUsage = "Data Encryption disable\\enable flag. Options: true\\false. Default: false. " +
		commonEnvVarUsageText + dataEncryptionDisabledEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "VC_REST_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		commonEnvVarUsageText + requestTokensEnvKey

	oAuthSecretFlagName      = "oauth-secret"
	oAuthSecretFlagShorthand = "o"
	oAuthSecretFlagUsage     = "oauth global secret, any string. Example: secret-for-signing-and-verifying-signatures"
	oAuthSecretFlagEnvKey    = "VC_OAUTH_SECRET"

	transientDataStoreTypeFlagName  = "transient-data-store-type"
	transientDataStoreTypeFlagUsage = "Transient data store type. " +
		"For now includes Fosite oAuth data, " +
		"encrypted claim data submitted by issuer during OIDC4CI issuance " + "(TTL configurable via " + claimDataTTLEnvKey + "), " +
		"OIDC4CI issuance transaction data " + "(TTL configurable via " + oidc4ciTransactionDataTTLEnvKey + "), " +
		"OIDC4CI issuance auth state store " + "(TTL configurable via " + oidc4ciAuthStateTTLEnvKey + "), " +
		"OIDC4VP transaction mapping " + "(TTL configurable via " + oidc4vpNonceTTLEnvKey + "), " +
		"OIDC4VP transaction data " + "(TTL configurable via " + oidc4vpTransactionDataTTLEnvKey + "), " +
		"notification data " + "(TTL configurable via " + oidc4ciAckDataTTLEnvKey + "), " +
		"encrypted claim data of OIDC4VP presentation transaction. " + "(TTL configurable via " + oidc4vpReceivedClaimsDataTTLEnvKey + "). " +
		"Possible values are \"redis\" or \"mongo\". Default is \"mongo\". " +
		commonEnvVarUsageText + transientDataStoreTypeFlagEnvKey
	transientDataStoreTypeFlagEnvKey = "VC_TRANSIENT_DATA_STORE_TYPE"

	oAuthClientsFilePathFlagName  = "oauth-client-file-path"
	oAuthClientsFilePathEnvKey    = "VC_OAUTH_CLIENTS_FILE_PATH"
	oAuthClientsFilePathFlagUsage = "Path to file with oauth clients. " +
		commonEnvVarUsageText + oAuthClientsFilePathEnvKey

	claimDataTTLFlagName  = "claim-data-ttl"
	claimDataTTLEnvKey    = "VC_CLAIM_DATA_TTL"
	claimDataTTLFlagUsage = "Claim data TTL in OIDC4VC pre-auth code flow. Defaults to 3600s. " +
		commonEnvVarUsageText + hostURLExternalEnvKey

	oidc4vpReceivedClaimsDataTTLFlagName  = "vc-oidc4vp-received-claims-data-ttl"
	oidc4vpReceivedClaimsDataTTLEnvKey    = "VC_OIDC4VP_RECEIVED_CLAIMS_DATA_TTL"
	oidc4vpReceivedClaimsDataTTLFlagUsage = "VP Received Claims data TTL in OIDC4VP pre-auth code flow. Defaults to 3600s. " +
		commonEnvVarUsageText + hostURLExternalEnvKey

	oidc4vpTransactionDataTTLFlagName  = "vc-oidc4vp-transaction-data-ttl"
	oidc4vpTransactionDataTTLEnvKey    = "VC_OIDC4VP_TRANSACTION_DATA_TTL"
	oidc4vpTransactionDataTTLFlagUsage = "VP Transaction data TTL in OIDC4VP pre-auth code flow. Defaults to 1h. " +
		commonEnvVarUsageText + oidc4vpTransactionDataTTLEnvKey

	oidc4ciTransactionDataTTLFlagName  = "vc-oidc4ci-transaction-data-ttl"
	oidc4ciTransactionDataTTLEnvKey    = "VC_OIDC4CI_TRANSACTION_DATA_TTL"
	oidc4ciTransactionDataTTLFlagUsage = "OIDC4CI transaction data TTL. Defaults to 15m. " +
		commonEnvVarUsageText + oidc4ciTransactionDataTTLEnvKey

	oidc4ciAckDataTTLFlagName  = "vc-oidc4ci-ack-data-ttl"
	oidc4ciAckDataTTLEnvKey    = "VC_OIDC4CI_ACK_DATA_TTL"
	oidc4ciAckDataTTLFlagUsage = "OIDC4CI ack data TTL. Defaults to 24h. " +
		commonEnvVarUsageText + oidc4ciAckDataTTLEnvKey

	oidc4ciAuthStateTTLFlagName  = "vc-oidc4ci-auth-state-ttl"
	oidc4ciAuthStateTTLEnvKey    = "VC_OIDC4CI_AUTH_STATE_TTL"
	oidc4ciAuthStateTTLFlagUsage = "OIDC4CI auth state data TTL. Defaults to 15m. " +
		commonEnvVarUsageText + oidc4ciAuthStateTTLEnvKey

	oidc4vpNonceTTLFlagName  = "vc-oidc4vp-nonce-data-ttl"
	oidc4vpNonceTTLEnvKey    = "VC_OIDC4VP_NONCE_DATA_TTL"
	oidc4vpNonceTTLFlagUsage = "VP nonce data TTL in OIDC4VP pre-auth code flow. Defaults to 15m. " +
		commonEnvVarUsageText + oidc4vpNonceTTLEnvKey

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

	credentialOfferRepositoryS3BucketFlagName  = "credential-offer-repository-s3-bucket"
	credentialOfferRepositoryS3BucketEnvKey    = "CREDENTIAL_OFFER_REPOSITORY_S3_BUCKET"
	credentialOfferRepositoryS3BucketFlagUsage = "credential-offer S3 Bucket"

	credentialOfferRepositoryS3RegionFlagName  = "credential-offer-repository-s3-region"
	credentialOfferRepositoryS3RegionEnvKey    = "CREDENTIAL_OFFER_REPOSITORY_S3_REGION"
	credentialOfferRepositoryS3RegionFlagUsage = "credential-offer S3 Region"

	credentialOfferRepositoryS3HostNameFlagName  = "credential-offer-repository-s3-hostname"
	credentialOfferRepositoryS3HostNameEnvKey    = "CREDENTIAL_OFFER_REPOSITORY_S3_HOSTNAME"
	credentialOfferRepositoryS3HostNameFlagUsage = "credential-offer S3 Hostname"

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

	credentialstatusTopicFlagName  = "credentialstatus-event-topic"
	credentialstatusTopicEnvKey    = "VC_REST_CREDENTIALSTATUS_EVENT_TOPIC"
	credentialstatusTopicFlagUsage = "The name of the credential status event topic. " + commonEnvVarUsageText + credentialstatusTopicEnvKey

	otelExporterTypeFlagName  = "otel-exporter-type"
	otelExporterTypeEnvKey    = "OTEL_EXPORTER_TYPE"
	otelExporterTypeFlagUsage = "The type of OpenTelemetry span exporter. Supported: JAEGER, STDOUT. " +
		"If not specified noop is used. " + commonEnvVarUsageText + otelExporterTypeEnvKey

	otelServiceNameFlagName  = "otel-service-name"
	otelServiceNameEnvKey    = "OTEL_SERVICE_NAME"
	otelServiceNameFlagUsage = "Logical name of the service that is traced. MUST be the same for all instances of " +
		"horizontally scaled services. Default: vcs. " + commonEnvVarUsageText + otelServiceNameEnvKey

	enableProfilerFlagName  = "enable-profiler"
	enableProfilerEnvKey    = "VC_REST_ENABLE_PROFILER"
	enableProfilerFlagUsage = "Enable pprof endpoints /debug/* " +
		commonEnvVarUsageText + enableProfilerEnvKey
	didMethodION = "ion"

	splitRequestTokenLength = 2

	defaultTracingServiceName    = "vcs"
	defaultInternalServerAddress = "0.0.0.0:50321"

	defaultHTTPDialTimeout   = 2 * time.Second
	defaultHTTPTimeout       = 20 * time.Second
	defaultForceAttemptHTTP2 = true

	redisStore = "redis"
)

const (
	defaultClaimDataTTL                 = time.Hour
	defaultOIDC4VPReceivedClaimsDataTTL = time.Hour
	defaultOIDC4VPTransactionDataTTL    = time.Hour
	defaultOIDC4VPNonceDataTTL          = 15 * time.Minute
	defaultOIDC4CITransactionDataTTL    = 15 * time.Minute
	defaultOIDC4CIAckDataTTL            = 24 * time.Hour
	defaultOIDC4CIAuthStateTTL          = 15 * time.Minute
	defaultDataEncryptionKeyLength      = 256
)

type startupParameters struct {
	hostURL                             string
	hostURLExternal                     string
	universalResolverURL                string
	orbDomain                           string
	mode                                string
	dbParameters                        *dbParameters
	redisParameters                     *redisParameters
	kmsParameters                       *kmsParameters
	token                               string
	requestTokens                       map[string]string
	logLevels                           string
	contextProviderURLs                 []string
	contextEnableRemote                 bool
	tlsParameters                       *tlsParameters
	httpParameters                      *httpParameters
	devMode                             bool
	oAuthSecret                         string
	oAuthClientsFilePath                string
	metricsProviderName                 string
	prometheusMetricsProviderParams     *prometheusMetricsProviderParams
	apiGatewayURL                       string
	requestObjectRepositoryType         string
	requestObjectRepositoryS3Bucket     string
	requestObjectRepositoryS3Region     string
	credentialOfferRepositoryS3Bucket   string
	credentialOfferRepositoryS3Region   string
	requestObjectRepositoryS3HostName   string
	credentialOfferRepositoryS3HostName string
	cslStoreType                        string
	cslStoreS3Bucket                    string
	cslStoreS3Region                    string
	cslStoreS3HostName                  string
	issuerEventTopic                    string
	verifierEventTopic                  string
	credentialStatusEventTopic          string
	tracingParams                       *tracingParams
	transientDataParams                 *transientDataParams
	dataEncryptionKeyID                 string
	dataEncryptionKeyLength             int
	dataEncryptionCompressorAlgo        string
	enableProfiler                      bool
	dataEncryptionDisabled              bool
}

type transientDataParams struct {
	storeType                    string
	claimDataTTL                 int32
	oidc4ciTransactionDataTTL    int32
	oidc4ciAckDataTTL            int32
	oidc4ciAuthStateTTL          int32
	oidc4vpNonceStoreDataTTL     int32
	oidc4vpTransactionDataTTL    int32
	oidc4vpReceivedClaimsDataTTL int32
}

type prometheusMetricsProviderParams struct {
	url string
}

type tracingParams struct {
	exporter    tracing.SpanExporterType
	serviceName string
}

type dbParameters struct {
	databaseType   string
	databaseURL    string
	databasePrefix string
}

type redisParameters struct {
	addrs      []string
	masterName string
	password   string
	disableTLS bool
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type httpParameters struct {
	timeout           time.Duration
	dialTimeout       time.Duration
	forceAttemptHTTP2 bool
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

	var prometheusMetricsProviderParamsVal *prometheusMetricsProviderParams
	if metricsProviderName == "prometheus" {
		prometheusMetricsProviderParamsVal, err = getPrometheusMetricsProviderParams(cmd)
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

	httpParams, err := getHTTPParameters(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := getDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	transientDataParameters, err := getTransientDataParams(cmd)
	if err != nil {
		return nil, err
	}

	redisParams, err := getRedisParameters(cmd, transientDataParameters.storeType)
	if err != nil {
		return nil, err
	}

	kmsParams, err := getKMSParameters(cmd)
	if err != nil {
		return nil, err
	}

	token := cmdutils.GetUserSetOptionalVarFromString(cmd, tokenFlagName, tokenEnvKey)

	dataEncryptionCompressionAlgo := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		dataEncryptionCompressionAlgorithmFlagName,
		dataEncryptionCompressionAlgorithmEnvKey,
	)

	dataEncryptionKeyID, err := cmdutils.GetUserSetVarFromString(
		cmd,
		dataEncryptionKeyIDFlagName,
		dataEncryptionKeyIDEnvKey,
		false,
	)
	if err != nil {
		return nil, err
	}

	dataEncryptionKeyLengthStr := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		dataEncryptionKeyLengthFlagName,
		dataEncryptionKeyLengthEnvKey,
	)
	dataEncryptionKeyLength := defaultDataEncryptionKeyLength

	if len(dataEncryptionKeyLengthStr) > 0 {
		if v, _ := strconv.Atoi(dataEncryptionKeyLengthStr); v > 0 {
			dataEncryptionKeyLength = v
		} else {
			logger.Warn("can not parse VC_REST_DATA_ENCRYPTION_KEY_LENGTH")
		}
	}

	dataEncryptionDisabled, _ := strconv.ParseBool(cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		dataEncryptionDisabledFlagName,
		dataEncryptionDisabledEnvKey,
	))

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

	credentialOfferRepositoryS3HostName := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		credentialOfferRepositoryS3HostNameFlagName,
		credentialOfferRepositoryS3HostNameEnvKey,
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

	credentialStatusTopic := cmdutils.GetUserSetOptionalVarFromString(cmd, credentialstatusTopicFlagName, credentialstatusTopicEnvKey)
	if credentialStatusTopic == "" {
		credentialStatusTopic = spi.CredentialStatusEventTopic
	}

	tracingParams, err := getTracingParams(cmd)
	if err != nil {
		return nil, err
	}

	credentialOfferRepositoryS3Bucket := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		credentialOfferRepositoryS3BucketFlagName,
		credentialOfferRepositoryS3BucketEnvKey,
	)
	credentialOfferRepositoryS3Region := cmdutils.GetUserSetOptionalVarFromString(
		cmd,
		credentialOfferRepositoryS3RegionFlagName,
		credentialOfferRepositoryS3RegionEnvKey,
	)

	if prometheusMetricsProviderParamsVal == nil {
		prometheusMetricsProviderParamsVal = &prometheusMetricsProviderParams{
			url: defaultInternalServerAddress,
		}
	}

	enableProfiler, _ := strconv.ParseBool(cmdutils.GetOptionalString(cmd, enableProfilerFlagName, enableProfilerEnvKey))

	return &startupParameters{
		hostURL:                             hostURL,
		hostURLExternal:                     hostURLExternal,
		universalResolverURL:                universalResolverURL,
		orbDomain:                           orbDomain,
		mode:                                mode,
		dbParameters:                        dbParams,
		redisParameters:                     redisParams,
		kmsParameters:                       kmsParams,
		tlsParameters:                       tlsParameters,
		httpParameters:                      httpParams,
		token:                               token,
		requestTokens:                       requestTokens,
		logLevels:                           loggingLevel,
		contextProviderURLs:                 contextProviderURLs,
		contextEnableRemote:                 contextEnableRemote,
		devMode:                             devMode,
		oAuthSecret:                         oAuthSecret,
		oAuthClientsFilePath:                oAuthClientsFilePath,
		metricsProviderName:                 metricsProviderName,
		prometheusMetricsProviderParams:     prometheusMetricsProviderParamsVal,
		apiGatewayURL:                       apiGatewayURL,
		requestObjectRepositoryType:         requestObjectRepositoryType,
		requestObjectRepositoryS3Bucket:     requestObjectRepositoryS3Bucket,
		requestObjectRepositoryS3Region:     requestObjectRepositoryS3Region,
		credentialOfferRepositoryS3Bucket:   credentialOfferRepositoryS3Bucket,
		credentialOfferRepositoryS3Region:   credentialOfferRepositoryS3Region,
		requestObjectRepositoryS3HostName:   requestObjectRepositoryS3HostName,
		credentialOfferRepositoryS3HostName: credentialOfferRepositoryS3HostName,
		cslStoreType:                        cslStoreType,
		cslStoreS3Bucket:                    cslStoreS3Bucket,
		cslStoreS3Region:                    cslStoreS3Region,
		cslStoreS3HostName:                  cslStoreS3HostName,
		issuerEventTopic:                    issuerTopic,
		verifierEventTopic:                  verifierTopic,
		credentialStatusEventTopic:          credentialStatusTopic,
		tracingParams:                       tracingParams,
		dataEncryptionKeyID:                 dataEncryptionKeyID,
		dataEncryptionKeyLength:             dataEncryptionKeyLength,
		enableProfiler:                      enableProfiler,
		dataEncryptionCompressorAlgo:        dataEncryptionCompressionAlgo,
		dataEncryptionDisabled:              dataEncryptionDisabled,
		transientDataParams:                 transientDataParameters,
	}, nil
}

func getTransientDataParams(cmd *cobra.Command) (*transientDataParams, error) {
	transientDataStoreType := cmdutils.GetUserSetOptionalVarFromString(cmd, transientDataStoreTypeFlagName, transientDataStoreTypeFlagEnvKey)

	claimDataTTL, err := getDuration(cmd, claimDataTTLFlagName, claimDataTTLEnvKey, defaultClaimDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4vpReceivedClaimsDataTTL, err := getDuration(cmd, oidc4vpReceivedClaimsDataTTLFlagName, oidc4vpReceivedClaimsDataTTLEnvKey, defaultOIDC4VPReceivedClaimsDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4vpTransactionDataTTL, err := getDuration(cmd, oidc4vpTransactionDataTTLFlagName, oidc4vpTransactionDataTTLEnvKey, defaultOIDC4VPTransactionDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4vpNonceStoreDataTTL, err := getDuration(cmd, oidc4vpNonceTTLFlagName, oidc4vpNonceTTLEnvKey, defaultOIDC4VPNonceDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4ciTransactionDataTTL, err := getDuration(
		cmd, oidc4ciTransactionDataTTLFlagName, oidc4ciTransactionDataTTLEnvKey, defaultOIDC4CITransactionDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4ciAckDataTTL, err := getDuration(
		cmd, oidc4ciAckDataTTLFlagName, oidc4ciAckDataTTLEnvKey, defaultOIDC4CIAckDataTTL)
	if err != nil {
		return nil, err
	}

	oidc4ciAuthStateTTL, err := getDuration(
		cmd, oidc4ciAuthStateTTLFlagName, oidc4ciAuthStateTTLEnvKey, defaultOIDC4CIAuthStateTTL)
	if err != nil {
		return nil, err
	}

	return &transientDataParams{
		storeType:                    transientDataStoreType,
		claimDataTTL:                 int32(claimDataTTL.Seconds()),
		oidc4ciTransactionDataTTL:    int32(oidc4ciTransactionDataTTL.Seconds()),
		oidc4ciAckDataTTL:            int32(oidc4ciAckDataTTL.Seconds()),
		oidc4ciAuthStateTTL:          int32(oidc4ciAuthStateTTL.Seconds()),
		oidc4vpReceivedClaimsDataTTL: int32(oidc4vpReceivedClaimsDataTTL.Seconds()),
		oidc4vpNonceStoreDataTTL:     int32(oidc4vpNonceStoreDataTTL.Seconds()),
		oidc4vpTransactionDataTTL:    int32(oidc4vpTransactionDataTTL.Seconds()),
	}, nil
}

func getHTTPParameters(cmd *cobra.Command) (*httpParameters, error) {
	httpTimeout, err := getDuration(cmd, httpTimeoutFlagName, httpTimeoutEnvKey, defaultHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpTimeoutFlagName, err)
	}

	httpDialTimeout, err := getDuration(cmd, httpDialTimeoutFlagName, httpDialTimeoutEnvKey, defaultHTTPDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpDialTimeoutFlagName, err)
	}

	forceAttemptHTTP2, err := getBoolean(cmd, httpForceAttemptHTTP2FlagName, httpForceAttemptHTTP2EnvKey, defaultForceAttemptHTTP2)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpForceAttemptHTTP2FlagName, err)
	}

	return &httpParameters{
		timeout:           httpTimeout,
		dialTimeout:       httpDialTimeout,
		forceAttemptHTTP2: forceAttemptHTTP2,
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

func getBoolean(cmd *cobra.Command, flagName, envKey string,
	defaultFlag bool) (bool, error) {
	flagStr, err := cmdutils.GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return defaultFlag, err
	}

	if flagStr == "" {
		return defaultFlag, nil
	}

	flag, err := strconv.ParseBool(flagStr)
	if err != nil {
		return defaultFlag, fmt.Errorf("invalid value [%s]: %w", flagStr, err)
	}

	return flag, nil
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

func getRedisParameters(cmd *cobra.Command, transientDataStoreType string) (*redisParameters, error) {
	redisURLs, err := cmdutils.GetStringArray(
		cmd, redisURLFlagName, redisURLEnvKey, transientDataStoreType != redisStore)
	if err != nil {
		return nil, err
	}

	redisSentinelMasterName := cmdutils.GetUserSetOptionalVarFromString(cmd,
		redisSentinelMasterNameFlagName, redisSentinelMasterNameEnvKey)

	redisAuthPassword := cmdutils.GetUserSetOptionalVarFromString(cmd,
		redisAuthPasswordFlagName, redisAuthPasswordEnvKey)

	disableTLS, _ := strconv.ParseBool(
		cmdutils.GetOptionalString(cmd, redisDisableTLSFlagName, redisDisableTLSEnvKey))

	return &redisParameters{
		addrs:      redisURLs,
		masterName: redisSentinelMasterName,
		password:   redisAuthPassword,
		disableTLS: disableTLS,
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
	serviceName := cmdutils.GetOptionalString(cmd, otelServiceNameFlagName, otelServiceNameEnvKey)
	if serviceName == "" {
		serviceName = defaultTracingServiceName
	}

	params := &tracingParams{
		exporter:    cmdutils.GetOptionalString(cmd, otelExporterTypeFlagName, otelExporterTypeEnvKey),
		serviceName: serviceName,
	}

	switch params.exporter {
	case tracing.None:
	case tracing.Jaeger:
	case tracing.Stdout:
		return params, nil
	default:
		return nil, fmt.Errorf("unsupported otel span exporter: %s", params.exporter)
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
	startCmd.Flags().StringArrayP(redisURLFlagName, "", nil, redisURLFlagUsage)
	startCmd.Flags().StringP(redisSentinelMasterNameFlagName, "", "", redisSentinelMasterNameFlagUsage)
	startCmd.Flags().String(redisAuthPasswordFlagName, "", redisAuthPasswordFlagUsage)
	startCmd.Flags().String(redisDisableTLSFlagName, "", redisDisableTLSFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringSliceP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tokenFlagName, "", "", tokenFlagUsage)
	startCmd.Flags().StringP(dataEncryptionKeyIDFlagName, "", "", dataEncryptionKeyIDFlagUsage)
	startCmd.Flags().StringP(dataEncryptionCompressionAlgorithmFlagName, "", "", dataEncryptionCompressionAlgorithmFlagUsage)
	startCmd.Flags().StringP(dataEncryptionKeyLengthFlagName, "", "", dataEncryptionKeyLengthFlagUsage)
	startCmd.Flags().StringP(dataEncryptionDisabledFlagName, "", "", dataEncryptionDisabledFlagUsage)
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

	startCmd.Flags().String(credentialOfferRepositoryS3BucketFlagName, "", credentialOfferRepositoryS3BucketFlagUsage)
	startCmd.Flags().String(credentialOfferRepositoryS3RegionFlagName, "", credentialOfferRepositoryS3RegionFlagUsage)
	startCmd.Flags().String(credentialOfferRepositoryS3HostNameFlagName, "", credentialOfferRepositoryS3HostNameFlagUsage)

	startCmd.Flags().String(cslStoreTypeFlagName, "", cslStoreFlagUsage)
	startCmd.Flags().String(cslStoreS3BucketFlagName, "", cslStoreS3BucketFlagUsage)
	startCmd.Flags().String(cslStoreS3RegionFlagName, "", cslStoreS3RegionFlagUsage)
	startCmd.Flags().String(cslStoreS3HostNameFlagName, "", cslStoreS3HostNameFlagUsage)

	startCmd.Flags().StringP(issuerTopicFlagName, "", "", issuerTopicFlagUsage)
	startCmd.Flags().StringP(verifierTopicFlagName, "", "", verifierTopicFlagUsage)
	startCmd.Flags().StringP(credentialstatusTopicFlagName, "", "", credentialstatusTopicFlagUsage)
	startCmd.Flags().StringP(claimDataTTLFlagName, "", "", claimDataTTLFlagUsage)
	startCmd.Flags().StringP(oidc4vpReceivedClaimsDataTTLFlagName, "", "", oidc4vpReceivedClaimsDataTTLFlagUsage)
	startCmd.Flags().StringP(oidc4vpTransactionDataTTLFlagName, "", "", oidc4vpTransactionDataTTLFlagUsage)
	startCmd.Flags().StringP(oidc4vpNonceTTLFlagName, "", "", oidc4vpNonceTTLFlagUsage)
	startCmd.Flags().StringP(oidc4ciTransactionDataTTLFlagName, "", "", oidc4ciTransactionDataTTLFlagUsage)
	startCmd.Flags().StringP(oidc4ciAckDataTTLFlagName, "", "", oidc4ciAckDataTTLFlagUsage)
	startCmd.Flags().StringP(oidc4ciAuthStateTTLFlagName, "", "", oidc4ciAuthStateTTLFlagUsage)

	startCmd.Flags().StringP(otelServiceNameFlagName, "", "", otelServiceNameFlagUsage)
	startCmd.Flags().StringP(otelExporterTypeFlagName, "", "", otelExporterTypeFlagUsage)
	startCmd.Flags().StringP(enableProfilerFlagName, "", "", enableProfilerFlagUsage)

	startCmd.Flags().StringP(httpTimeoutFlagName, "", "", httpTimeoutFlagUsage)
	startCmd.Flags().StringP(httpDialTimeoutFlagName, "", "", httpDialTimeoutFlagUsage)
	startCmd.Flags().StringP(httpForceAttemptHTTP2FlagName, "", "", httpForceAttemptHTTP2FlagUsage)
	startCmd.Flags().String(transientDataStoreTypeFlagName, "", transientDataStoreTypeFlagUsage)

	profilereader.AddFlags(startCmd)
}
