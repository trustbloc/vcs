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
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certPath, keyPath string, handler http.Handler) error {
	return nil
}

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
			"Neither host-url (command line flag) nor COMPARATOR_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing dsn arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"failed to configure dsn: Neither dsn (command line flag) nor COMPARATOR_DSN (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing did domain arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://test",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither did-domain (command line flag) nor COMPARATOR_DID_DOMAIN (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing csh url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + didDomainFlagName, "did",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither csh-url (command line flag) nor COMPARATOR_CSH_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing vault url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + didDomainFlagName, "did",
			"--" + cshURLFlagName, "localhost:8081",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither vault-url (command line flag) nor COMPARATOR_VAULT_URL (environment variable) have been set.",
			err.Error())
	})
}

func TestNotSupportedDSN(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + datasourceNameFlagName, "mem1://test",
		"--" + didDomainFlagName, "did",
		"--" + cshURLFlagName, "localhost:8081",
		"--" + vaultURLFlagName, "localhost:8081",
		"--" + requestTokensFlagName, "token2=tk2=1",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported storage driver: mem1")
}

func TestFailedToConnectToDB(t *testing.T) {
	t.Run("test couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "couchdb://url",
			"--" + didDomainFlagName, "did",
			"--" + datasourceTimeoutFlagName, "1",
			"--" + cshURLFlagName, "localhost:8081",
			"--" + vaultURLFlagName, "localhost:8081",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to connect to storage at url")
	})

	t.Run("test mysql", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mysql://url",
			"--" + didDomainFlagName, "did",
			"--" + datasourceTimeoutFlagName, "1",
			"--" + cshURLFlagName, "localhost:8081",
			"--" + vaultURLFlagName, "localhost:8081",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to connect to storage at url")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "COMPARATOR_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + datasourceNameFlagName, "mem://test",
		"--" + didDomainFlagName, "did",
		"--" + cshURLFlagName, "https://localhost:8081",
		"--" + vaultURLFlagName, "https://localhost:8081",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create DID")
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
}
