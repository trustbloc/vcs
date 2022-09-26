/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/trustbloc/vcs/pkg/kms"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/vcs/cmd/common"
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

	databaseTypeMongoDBOption = "mongodb"

	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodWeb     = "web"
	didMethodFactom  = "factom"

	splitRequestTokenLength = 2
)

type startupParameters struct {
	hostURL              string
	blocDomain           string
	hostURLExternal      string
	universalResolverURL string
	mode                 string
	dbParameters         *dbParameters
	kmsParameters        *kmsParameters
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
	databaseType   string
	databaseURL    string
	databasePrefix string
}

type kmsParameters struct {
	kmsType                  kms.Type
	kmsEndpoint              string
	kmsRegion                string
	kmsSecretsDatabaseType   string
	kmsSecretsDatabaseURL    string
	kmsSecretsDatabasePrefix string
	secretLockKeyPath        string
}

// nolint: gocyclo,funlen
func getStartupParameters(cmd *cobra.Command) (*startupParameters, error) {
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

	kmsParams, err := getKMSParameters(cmd)
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

	return &startupParameters{
		hostURL:              hostURL,
		blocDomain:           blocDomain,
		hostURLExternal:      hostURLExternal,
		universalResolverURL: universalResolverURL,
		mode:                 mode,
		dbParameters:         dbParams,
		kmsParameters:        kmsParams,
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
	}, nil
}

func supportedKmsType(kmsType kms.Type) bool {
	if kmsType != kms.Local && kmsType != kms.Web && kmsType != kms.AWS {
		return false
	}

	return true
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
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens
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
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringSliceP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tokenFlagName, "", "", tokenFlagUsage)
	startCmd.Flags().StringSliceP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
	startCmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
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
	startCmd.Flags().String(kmsRegionFlagName, "", kmsRegionFlagUsage)
}
