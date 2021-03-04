/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/cmd/common"
)

func TestListenAndServe(t *testing.T) {
	var w HTTPServer
	err := w.ListenAndServe("wronghost", "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "address wronghost: missing port in address")
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor CHS_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("missing database url arg", func(t *testing.T) {
		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + common.DatabasePrefixFlagName, "test",
		}
		startCmd := GetStartCmd(&mockServer{})

		startCmd.SetArgs(args)
		err := startCmd.Execute()
		require.Error(t, err)
		require.EqualError(t, err, "failed to configure dbURL: Neither database-url (command line flag) nor DATABASE_URL (environment variable) have been set.") // nolint:lll
	})
}

func TestStartCmdWithInvalidArgs(t *testing.T) {
	t.Run("invalid database url", func(t *testing.T) {
		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + common.DatabaseURLFlagName, "invalid",
			"--" + common.DatabasePrefixFlagName, "test",
		}
		startCmd := GetStartCmd(&mockServer{})

		startCmd.SetArgs(args)
		err := startCmd.Execute()
		require.Error(t, err)
		require.EqualError(t, err, "failed to init provider: failed to parse invalid: invalid dbURL invalid")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "CHS_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + common.DatabaseURLFlagName, "mem://test",
		"--" + common.DatabasePrefixFlagName, "test",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestTLSInvalidArgs(t *testing.T) {
	t.Run("test wrong tls cert pool flag", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + tlsSystemCertPoolFlagName, "wrong",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
	})

	t.Run("test invalid TLS pool path", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + common.DatabaseURLFlagName, "mem://test",
			"--" + common.DatabasePrefixFlagName, "test",
			"--" + tlsSystemCertPoolFlagName, "true",
			"--" + tlsCACertsFlagName, "INVALID",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.EqualError(t, err,
			"failed to get tls cert pool: failed to read cert: open INVALID: no such file or directory")
	})
}

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certPath, keyPath string, handler http.Handler) error {
	return nil
}
