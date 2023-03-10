/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
)

const (
	// LogLevelFlagName is the flag name used for setting the default log level.
	LogLevelFlagName = "log-level"
	// LogLevelEnvKey is the env var name used for setting the default log level.
	LogLevelEnvKey = "LOG_LEVEL"
	// LogLevelFlagShorthand is the shorthand flag name used for setting the default log level.
	LogLevelFlagShorthand = "l"
	// LogLevelPrefixFlagUsage is the usage text for the log level flag.
	LogLevelPrefixFlagUsage = "Sets logging levels for individual modules as well as the default level. `+" +
		"`The format of the string is as follows: module1=level1:module2=level2:defaultLevel. `+" +
		"`Supported levels are: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		"`Example: oidc4vp=INFO:oidc4vp-service=WARNING:INFO. `+" +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + LogLevelEnvKey
)

// SetDefaultLogLevel sets the default log level.
func SetDefaultLogLevel(logger *log.Log, userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warn(`User log level is not a valid. It must be one of the following: `+
			log.PANIC.String()+", "+
			log.FATAL.String()+", "+
			log.ERROR.String()+", "+
			log.WARNING.String()+", "+
			log.INFO.String()+", "+
			log.DEBUG.String()+". Defaulting to info.", logfields.WithUserLogLevel(userLogLevel))

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Info(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}
