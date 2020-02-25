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

	t.Run("test blank sidetree url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, "test", "--" + sideTreeURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "sidetree-url value is empty", err.Error())
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
		"localhost:8081", "--" + sideTreeURLFlagName, "localhost:8082"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(edvURLEnvKey, "localhost:8081")
	require.Nil(t, err)

	err = os.Setenv(sideTreeURLEnvKey, "localhost:8082")
	require.Nil(t, err)

	err = startCmd.Execute()

	require.Nil(t, err)
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

func TestCreateVDRI(t *testing.T) {
	t.Run("test error from create new sidetree vdri", func(t *testing.T) {
		v, err := createVDRI("wrong", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new sidetree vdri")
		require.Nil(t, v)
	})

	t.Run("test error from create new sidetree vdri", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{sideTreeURL: "wrong"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new sidetree vdri")
	})

	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		v, err := createVDRI("localhost:8082", "wrong", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
		require.Nil(t, v)
	})

	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{sideTreeURL: "localhost:8082", universalResolverURL: "wrong"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createVDRI("localhost:8082", "localhost:8083", nil)
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
