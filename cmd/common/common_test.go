/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/logutil-go/pkg/log"
)

const testLogModuleName = "test"

var logger = log.New(testLogModuleName)

func TestSetLogLevel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(logger, "debug")

		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(logger, "mango")

		// Should remain unchanged
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func resetLoggingLevels() {
	log.SetLevel("", log.INFO)
}
