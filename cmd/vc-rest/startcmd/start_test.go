/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start vc-rest", startCmd.Short)
	require.Equal(t, "Start vc-rest inside the edge-service", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "", "--" + edvURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})

	t.Run("test blank edv url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "edv-url value is empty", err.Error())
	})

	t.Run("test blank bloc domain arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, "test", "--" + blocDomainFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "bloc-domain value is empty", err.Error())
	})

	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "database-type value is empty", err.Error())
	})

	t.Run("test blank mode type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + modeFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "mode value is empty", err.Error())
	})

	t.Run("invalid mode", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{mode: "invalid"}, nil)
		require.Error(t, err)

		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported mode")
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor VC_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing edv url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither edv-url (command line flag) nor EDV_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "VC_REST_HOST_URL value is empty", err.Error())
	})

	t.Run("test blank edv url env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "localhost:8080")
		require.NoError(t, err)

		err = os.Setenv(edvURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "EDV_REST_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)

	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestCreateProvider(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{databaseType: databaseTypeCouchDBOption}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})

	t.Run("test invalid database type", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{databaseType: "data1"}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func TestCreateVDRI(t *testing.T) {
	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		v, err := createVDRI("wrong", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
		require.Nil(t, v)
	})

	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{universalResolverURL: "wrong"}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createVDRI("localhost:8083", nil)
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestCreateKMS(t *testing.T) {
	t.Run("test error from create new kms", func(t *testing.T) {
		v, err := createKMS(&MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new kms")
		require.Nil(t, v)
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createKMS(&MockStoreProvider{})
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(edvURLEnvKey, "localhost:8081")
	require.NoError(t, err)

	err = os.Setenv(blocDomainEnvKey, "domain")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(edvURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(blocDomainEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	ErrOpenStoreHandle error
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	return nil, s.ErrOpenStoreHandle
}

// Close closes all stores created under this store provider
func (s *MockStoreProvider) Close() error {
	return nil
}

// CloseStore closes store for given name space
func (s *MockStoreProvider) CloseStore(name string) error {
	return nil
}
