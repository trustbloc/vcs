/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/trustbloc/vcs/internal/pkg/log"

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
func SetDefaultLogLevel(logger *log.Log, userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warn(`User log level is not a valid. It must be one of the following: `+
			log.PANIC.String()+", "+
			log.FATAL.String()+", "+
			log.ERROR.String()+", "+
			log.WARNING.String()+", "+
			log.INFO.String()+", "+
			log.DEBUG.String()+". Defaulting to info.", log.WithUserLogLevel(userLogLevel))

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Info(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}
