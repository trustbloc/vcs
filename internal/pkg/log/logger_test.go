/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockWriter struct {
	*bytes.Buffer
}

func (m *mockWriter) Sync() error {
	return nil
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: bytes.NewBuffer(nil)}
}

func TestLogger(t *testing.T) {
	const module = "sample-module"

	t.Run("Default level", func(t *testing.T) {
		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debug("Sample debug log")
		logger.Info("Sample info log")
		logger.Warn("Sample warn log")
		logger.Error("Sample error log")

		require.Panics(t, func() {
			logger.Panic("Sample panic log")
		})

		require.NotContains(t, stdOut.Buffer.String(), "DEBUG")
		require.Contains(t, stdOut.Buffer.String(), "INFO")
		require.Contains(t, stdOut.Buffer.String(), "WARN")
		require.NotContains(t, stdOut.Buffer.String(), "PANIC")
		require.NotContains(t, stdOut.Buffer.String(), "FATAL")

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})

	t.Run("DEBUG", func(t *testing.T) {
		SetLevel(module, DEBUG)

		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debug("Sample debug log")
		logger.Info("Sample info log")
		logger.Warn("Sample warn log")
		logger.Error("Sample error log")

		require.Panics(t, func() {
			logger.Panic("Sample panic log")
		})

		require.Contains(t, stdOut.Buffer.String(), "DEBUG")
		require.Contains(t, stdOut.Buffer.String(), "INFO")
		require.Contains(t, stdOut.Buffer.String(), "WARN")
		require.NotContains(t, stdOut.Buffer.String(), "PANIC")
		require.NotContains(t, stdOut.Buffer.String(), "FATAL")

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})

	t.Run("ERROR", func(t *testing.T) {
		SetLevel(module, ERROR)

		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debug("Sample debug log")
		logger.Info("Sample info log")
		logger.Warn("Sample warn log")
		logger.Error("Sample error log")

		require.Panics(t, func() {
			logger.Panic("Sample panic log")
		})

		require.Empty(t, stdOut.Buffer.String())

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})
}

// TestAllLevels tests logging level behaviour
// logging levels can be set per modules, if not set then it will default to 'INFO'.
func TestAllLevels(t *testing.T) {
	module := "sample-module-critical"

	SetLevel(module, FATAL)
	require.Equal(t, FATAL, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL}, []Level{PANIC, ERROR, WARNING, INFO, DEBUG})

	SetLevel(module, PANIC)
	require.Equal(t, PANIC, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC}, []Level{ERROR, WARNING, INFO, DEBUG})

	module = "sample-module-error"
	SetLevel(module, ERROR)
	require.Equal(t, ERROR, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR}, []Level{WARNING, INFO, DEBUG})

	module = "sample-module-warning"
	SetLevel(module, WARNING)
	require.Equal(t, WARNING, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING}, []Level{INFO, DEBUG})

	module = "sample-module-info"
	SetLevel(module, INFO)
	require.Equal(t, INFO, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING, INFO}, []Level{DEBUG})

	module = "sample-module-debug"
	SetLevel(module, DEBUG)
	require.Equal(t, DEBUG, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING, INFO, DEBUG}, []Level{})
}

func TestGetAllLevels(t *testing.T) {
	sampleModuleCritical := "sample-module-critical"
	SetLevel(sampleModuleCritical, PANIC)

	sampleModuleWarning := "sample-module-warning"
	SetLevel(sampleModuleWarning, WARNING)

	allLogLevels := getAllLevels()
	require.Equal(t, PANIC, allLogLevels[sampleModuleCritical])
	require.Equal(t, WARNING, allLogLevels[sampleModuleWarning])
}

// TestLogLevel testing 'LogLevel()' used for parsing log levels from strings.
func TestLogLevel(t *testing.T) {
	verifyLevelsNoError := func(expected Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(FATAL, "fatal", "FATAL")
	verifyLevelsNoError(PANIC, "panic", "PANIC")
	verifyLevelsNoError(ERROR, "error", "ERROR")
	verifyLevelsNoError(WARNING, "warn", "WARN", "warning", "WARNING")
	verifyLevelsNoError(DEBUG, "debug", "DEBUG")
	verifyLevelsNoError(INFO, "info", "INFO")
}

// TestParseLevelError testing 'LogLevel()' used for parsing log levels from strings.
func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func TestParseString(t *testing.T) {
	require.Equal(t, "FATAL", FATAL.String())
	require.Equal(t, "PANIC", PANIC.String())
	require.Equal(t, "ERROR", ERROR.String())
	require.Equal(t, "WARN", WARNING.String())
	require.Equal(t, "INFO", INFO.String())
	require.Equal(t, "DEBUG", DEBUG.String())
}

func TestSetSpecLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=panic:error"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, PANIC, GetLevel("module2"))
		require.Equal(t, ERROR, GetLevel(""))
	})

	t.Run("Successfully set logging levels - no default", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=panic"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, PANIC, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("Module1=InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("debug:debug")
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple default values found")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})
}

func TestLogSpecGet(t *testing.T) {
	resetLoggingLevels()

	spec := GetSpec()

	t.Logf("Got spec: %s", spec)

	require.Contains(t, spec, "module1=INFO")
	require.Contains(t, spec, "module2=INFO")
	require.Contains(t, spec, ":INFO")
}

func TestLogLevels(t *testing.T) {
	mlevel := newModuleLevels()

	mlevel.Set("module-xyz-info", INFO)
	mlevel.Set("module-xyz-debug", DEBUG)
	mlevel.Set("module-xyz-error", ERROR)
	mlevel.Set("module-xyz-warning", WARNING)
	mlevel.Set("module-xyz-panic", PANIC)

	// Run info level checks
	require.True(t, mlevel.isEnabled("module-xyz-info", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-info", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-info", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-info", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-info", DEBUG))

	// Run debug level checks
	require.True(t, mlevel.isEnabled("module-xyz-debug", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-debug", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-debug", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-debug", INFO))
	require.True(t, mlevel.isEnabled("module-xyz-debug", DEBUG))

	// Run warning level checks
	require.True(t, mlevel.isEnabled("module-xyz-warning", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-warning", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-warning", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-warning", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-warning", DEBUG))

	// Run error level checks
	require.True(t, mlevel.isEnabled("module-xyz-error", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-error", ERROR))
	require.False(t, mlevel.isEnabled("module-xyz-error", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-error", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-error", DEBUG))

	// Run error panic checks
	require.True(t, mlevel.isEnabled("module-xyz-panic", PANIC))
	require.False(t, mlevel.isEnabled("module-xyz-panic", ERROR))
	require.False(t, mlevel.isEnabled("module-xyz-panic", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-panic", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-panic", DEBUG))

	// Run default log level check --> which is info level
	require.True(t, mlevel.isEnabled("module-xyz-random-module", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-random-module", DEBUG))
}

func resetLoggingLevels() {
	SetLevel("module1", INFO)
	SetLevel("module2", INFO)
	SetDefaultLevel(INFO)
}

func verifyLevels(t *testing.T, module string, enabled, disabled []Level) {
	t.Helper()

	for _, level := range enabled {
		require.True(t, levels.isEnabled(module, level),
			"expected level [%s] to be enabled for module [%s]", level, module)
	}

	for _, level := range disabled {
		require.False(t, levels.isEnabled(module, level),
			"expected level [%s] to be disabled for module [%s]", level, module)
	}
}
