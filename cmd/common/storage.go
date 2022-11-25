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
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/cmdutil-go/pkg/utils/cmd"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
)

const (
	// DatabaseURLFlagName is the database url.
	DatabaseURLFlagName = "database-url"
	// DatabaseURLFlagUsage describes the usage.
	DatabaseURLFlagUsage = "Database URL with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'," +
		" 'mongodb://mongodb.example.com:27017'." +
		" Supported drivers are [mongodb]." +
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
var supportedAriesStorageProviders = map[string]func(string, string) (storage.Provider, error){
	"mysql": func(dbURL, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dbURL, mysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	"couchdb": func(dbURL, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dbURL, couchdb.WithDBPrefix(prefix))
	},
	"mongodb": func(dbURL, prefix string) (storage.Provider, error) {
		return mongodb.NewProvider(dbURL, mongodb.WithDBPrefix(prefix))
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

// InitStore provider.
func InitStore(params *DBParameters, logger *log.Log) (storage.Provider, error) {
	driver, url, err := parseURL(params.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", params.URL, err)
	}

	providerFunc, supported := supportedAriesStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var provider storage.Provider

	err = retry(
		func() error {
			var openErr error
			provider, openErr = providerFunc(url, params.Prefix)
			return openErr
		},
		params.Timeout,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init aries storage provider: %w", err)
	}

	return provider, nil
}

func parseURL(u string) (string, string, error) {
	const urlParts = 2

	parsed := strings.SplitN(u, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", u)
	}

	driver := parsed[0]

	if driver == "mongodb" {
		// The MongoDB storage provider needs the full connection string (including the driver as part of it).
		return driver, u, nil
	}

	dsn := strings.TrimPrefix(parsed[1], "//")

	return driver, dsn, nil
}

func retry(task func() error, numRetries uint64, logger *log.Log) error {
	const sleep = 1 * time.Second

	return backoff.RetryNotify(
		task,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warn("Failed to connect to storage, will sleep before trying again.",
				logfields.WithSleep(t), log.WithError(retryErr))
		},
	)
}
