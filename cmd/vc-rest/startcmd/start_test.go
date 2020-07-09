/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/cmd/common"
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
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + edvURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + modeFlagName, "invalid"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
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

func TestStartCmdCreateKMSFailure(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption, "--" + kmsSecretsDatabaseURLFlagName,
		"badURL"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to create db")
}

func TestStartCmdWithNegativeMaxRetries(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + maxRetriesFlagName, "-5"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, `the given max retries value "-5" is not a valid non-negative integer: `+
		`strconv.ParseUint: parsing "-5": invalid syntax`)
}

func TestStartCmdWithNegativeInitialBackoff(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + initialBackoffMillisecFlagName, "-500"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, `the given initial backoff value "-500" is not a valid non-negative integer: `+
		`strconv.ParseUint: parsing "-500": invalid syntax`)
}

func TestStartCmdWithInvalidFloatingPointBackoffFactor(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + backoffFactorFlagName, "1.1.1"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, `the given backoff factor "1.1.1" is not a valid floating point number: `+
		`strconv.ParseFloat: parsing "1.1.1": invalid syntax`)
}

func TestStartCmdWithNegativeBackoffFactor(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + backoffFactorFlagName, "-2"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Equal(t, errNegativeBackoffFactor, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + edvURLFlagName,
		"localhost:8081", "--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
		"--" + requestTokensFlagName, "token1=tk1", "--" + requestTokensFlagName, "token2=tk2",
		"--" + requestTokensFlagName, "token2=tk2=1", "--" + common.LogLevelFlagName, log.ParseString(log.ERROR)}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Nil(t, err)
	require.Equal(t, log.ERROR, log.GetLevel(""))
}

func TestHealthCheck(t *testing.T) {
	b := &httptest.ResponseRecorder{}
	healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, databaseTypeMemOption)

	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestCreateProviders(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: databaseTypeCouchDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})
	t.Run("test error from create new kms secrets couchdb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{databaseType: databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeCouchDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})
	t.Run("test invalid database type", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: "data1"}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
	t.Run("test invalid kms secrets database type", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{databaseType: databaseTypeMemOption,
				kmsSecretsDatabaseType: "data1"}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func TestCreateKMS(t *testing.T) {
	t.Run("fail to open master key store", func(t *testing.T) {
		localKMS, err := createKMS(&edgeServiceProviders{
			kmsSecretsProvider: &ariesmockstorage.MockStoreProvider{FailNamespace: "masterkey"},
		})

		require.Nil(t, localKMS)
		require.EqualError(t, err, "failed to open store for name space masterkey")
	})
	t.Run("fail to create master key service", func(t *testing.T) {
		masterKeyStore := ariesmockstorage.MockStore{
			Store:     make(map[string][]byte),
			ErrPut:    nil,
			ErrGet:    nil,
			ErrItr:    nil,
			ErrDelete: nil,
		}

		err := masterKeyStore.Put("masterkey", []byte(""))
		require.NoError(t, err)

		localKMS, err := createKMS(&edgeServiceProviders{
			kmsSecretsProvider: &ariesmockstorage.MockStoreProvider{Store: &masterKeyStore},
		})
		require.EqualError(t, err, "masterKeyReader is empty")
		require.Nil(t, localKMS)
	})
}

func TestCreateVDRI(t *testing.T) {
	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		v, err := createVDRI("wrong", &tls.Config{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
		require.Nil(t, v)
	})

	t.Run("test error from create new universal resolver vdri", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{universalResolverURL: "wrong",
			dbParameters: &dbParameters{databaseType: "mem", kmsSecretsDatabaseType: "mem"}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdri")
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createVDRI("localhost:8083", &tls.Config{})
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestAcceptedDIDs(t *testing.T) {
	t.Run("Test accepted DID methods", func(t *testing.T) {
		tests := []struct {
			method string
			result bool
		}{
			{
				method: didMethodVeres,
				result: true,
			},
			{
				method: didMethodKey,
				result: true,
			},
			{
				method: didMethodSov,
				result: true,
			},
			{
				method: didMethodElement,
				result: true,
			},
			{
				method: didMethodWeb,
				result: true,
			},
			{
				method: "edge",
				result: false,
			},
			{
				method: "invalid",
				result: false,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.method, func(t *testing.T) {
				require.Equal(t, tc.result, acceptsDID(tc.method))
			})
		}
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, databaseTypeMemOption)

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestPrepareMasterKeyReader(t *testing.T) {
	t.Run("Unexpected error when trying to retrieve master key from store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: errors.New("testError")}})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
	t.Run("Error when putting newly generated master key into store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: storage.ErrDataNotFound,
					ErrPut: errors.New("testError")}})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
}

func TestValidateAuthorizationBearerToken(t *testing.T) {
	t.Run("test invalid token", func(t *testing.T) {
		header := make(map[string][]string)
		header["Authorization"] = []string{"Bearer tk1"}
		require.False(t, validateAuthorizationBearerToken(&httptest.ResponseRecorder{},
			&http.Request{Header: header}, "tk2"))
	})

	t.Run("test valid token", func(t *testing.T) {
		header := make(map[string][]string)
		header["Authorization"] = []string{"Bearer tk1"}
		require.True(t, validateAuthorizationBearerToken(&httptest.ResponseRecorder{},
			&http.Request{Header: header}, "tk1"))
	})
}

func setEnvVars(t *testing.T, databaseType string) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(edvURLEnvKey, "localhost:8081")
	require.NoError(t, err)

	err = os.Setenv(blocDomainEnvKey, "domain")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseType)
	require.NoError(t, err)

	err = os.Setenv(kmsSecretsDatabaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(edvURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(blocDomainEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsSecretsDatabasePrefixEnvKey)
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
