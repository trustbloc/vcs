/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	ariescouchdb "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmysql "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mysql"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
)

const (
	// DatabaseURLFlagName is the database url.
	DatabaseURLFlagName = "database-url"
	// DatabaseURLFlagUsage describes the usage.
	DatabaseURLFlagUsage = "Database URL with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, mysql, couchdb]." +
		" Alternatively, this can be set with the following environment variable: " + DatabaseURLEnvKey
	// DatabaseURLEnvKey is the databaes url.
	DatabaseURLEnvKey = "DATABASE_URL"

	// DatabaseTimeoutFlagName is the database timeout.
	DatabaseTimeoutFlagName = "database-timeout"
	// DatabaseTimeoutFlagUsage describes the usage.
	DatabaseTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: " + string(rune(DatabaseTimeoutDefault)) + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + DatabaseTimeoutEnvKey
	// DatabaseTimeoutEnvKey is the database timeout.
	DatabaseTimeoutEnvKey = "DATABASE_TIMEOUT"

	// DatabasePrefixFlagName is the storage prefix.
	DatabasePrefixFlagName = "database-prefix"
	// DatabasePrefixEnvKey is the storage prefix.
	DatabasePrefixEnvKey = "DATABASE_PREFIX"
	// DatabasePrefixFlagUsage describes the usage.
	DatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		"Alternatively, this can be set with the following environment variable: " + DatabasePrefixEnvKey

	// DatabaseTimeoutDefault is the default storage timeout.
	DatabaseTimeoutDefault = 30
)

// DBParameters holds database configuration.
type DBParameters struct {
	URL     string
	Prefix  string
	Timeout uint64
}

// nolint:gochecknoglobals
var supportedEdgeStorageProviders = map[string]func(string, string) (interface{}, error){
	"mysql": func(dbURL, prefix string) (interface{}, error) {
		return mysql.NewProvider(dbURL, mysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (interface{}, error) { // nolint:unparam
		return memstore.NewProvider(), nil
	},
	"couchdb": func(dbURL, prefix string) (interface{}, error) {
		return couchdbstore.NewProvider(dbURL, couchdbstore.WithDBPrefix(prefix))
	},
}

// nolint:gochecknoglobals
var supportedAriesStorageProviders = map[string]func(string, string) (interface{}, error){
	"mysql": func(dbURL, prefix string) (interface{}, error) {
		return ariesmysql.NewProvider(dbURL, ariesmysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (interface{}, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	"couchdb": func(dbURL, prefix string) (interface{}, error) {
		return ariescouchdb.NewProvider(dbURL, ariescouchdb.WithDBPrefix(prefix))
	},
}

// Flags registers common command flags.
func Flags(cmd *cobra.Command) {
	cmd.Flags().StringP(DatabaseURLFlagName, "", "", DatabaseURLFlagUsage)
	cmd.Flags().StringP(DatabasePrefixFlagName, "", "", DatabasePrefixFlagUsage)
	cmd.Flags().StringP(DatabaseTimeoutFlagName, "", "", DatabaseTimeoutFlagUsage)
}

// DBParams fetches the DB parameters configured for this command.
func DBParams(cmd *cobra.Command) (*DBParameters, error) {
	var err error

	params := &DBParameters{}

	params.URL, err = cmdutils.GetUserSetVarFromString(cmd, DatabaseURLFlagName, DatabaseURLEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dbURL: %w", err)
	}

	params.Prefix, err = cmdutils.GetUserSetVarFromString(cmd, DatabasePrefixFlagName, DatabasePrefixEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dbPrefix: %w", err)
	}

	timeout, err := cmdutils.GetUserSetVarFromString(cmd, DatabaseTimeoutFlagName, DatabaseTimeoutEnvKey, true)
	if err != nil && !strings.Contains(err.Error(), "value is empty") {
		return nil, fmt.Errorf("failed to configure dbTimeout: %w", err)
	}

	if timeout == "" {
		timeout = strconv.Itoa(DatabaseTimeoutDefault)
	}

	params.Timeout, err = strconv.ParseUint(timeout, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dbTimeout %s: %w", timeout, err)
	}

	return params, nil
}

// InitEdgeStore provider.
func InitEdgeStore(params *DBParameters, logger log.Logger) (storage.Provider, error) {
	provider, err := initStore(params, supportedEdgeStorageProviders, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to init aries storage provider: %w", err)
	}

	edgeProvider := provider.(storage.Provider) // nolint:errcheck // the implementation is guaranteed to be correct

	return edgeProvider, nil
}

// InitAriesStore provider.
func InitAriesStore(params *DBParameters, logger log.Logger) (ariesstorage.Provider, error) {
	provider, err := initStore(params, supportedAriesStorageProviders, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to init aries storage provider: %w", err)
	}

	ariesProvider := provider.(ariesstorage.Provider) // nolint:errcheck // the implementation is guaranteed to be correct

	return ariesProvider, nil
}

func initStore(params *DBParameters,
	providers map[string]func(string, string) (interface{}, error), logger log.Logger) (interface{}, error) {
	driver, url, err := parseURL(params.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", params.URL, err)
	}

	providerFunc, supported := providers[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store interface{}

	err = retry(
		func() error {
			var openErr error
			store, openErr = providerFunc(url, params.Prefix)
			return openErr
		},
		params.Timeout,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init aries storage provider: %w", err)
	}

	return store, nil
}

func parseURL(u string) (string, string, error) {
	const urlParts = 2

	parsed := strings.SplitN(u, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", u)
	}

	driver := parsed[0]
	dsn := strings.TrimPrefix(parsed[1], "//")

	return driver, dsn, nil
}

func retry(task func() error, numRetries uint64, logger log.Logger) error {
	const sleep = 1 * time.Second

	return backoff.RetryNotify(
		task,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
}
