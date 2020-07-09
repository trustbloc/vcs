/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/trustbloc/edge-core/pkg/log"

const (
	// LogLevelFlagName is the flag name used for setting the default log level.
	LogLevelFlagName = "log-level"
	// LogLevelEnvKey is the env var name used for setting the default log level.
	LogLevelEnvKey = "LOG_LEVEL"
	// LogLevelFlagShorthand is the shorthand flag name used for setting the default log level.
	LogLevelFlagShorthand = "l"
	// LogLevelPrefixFlagUsage is the usage text for the log level flag.
	LogLevelPrefixFlagUsage = "Logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + LogLevelEnvKey
)

// SetDefaultLogLevel sets the default log level.
func SetDefaultLogLevel(logger log.Logger, userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warnf(`%s is not a valid logging level. It must be one of the following: `+
			log.ParseString(log.CRITICAL)+", "+
			log.ParseString(log.ERROR)+", "+
			log.ParseString(log.WARNING)+", "+
			log.ParseString(log.INFO)+", "+
			log.ParseString(log.DEBUG)+". Defaulting to info.", userLogLevel)

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Infof(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}
