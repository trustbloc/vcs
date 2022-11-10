/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/cmd/common"
)

const (
	mongoDBConnString  = "mongodb://localhost:27018"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
	profilePathFlag    = "profiles-file-path"
	profilePathEnv     = "VC_REST_PROFILES_FILE_PATH"
)

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd()

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start vc-rest", startCmd.Short)
	require.Equal(t, "Start vc-rest inside the vcs", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "host-url value is empty")
	})

	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + databaseTypeFlagName, "",
			"--" + oAuthSecretFlagName, "secret",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "database-type value is empty")
	})

	t.Run("test blank mode type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + oAuthSecretFlagName, "test",
			"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
			"--" + modeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "mode value is empty")
	})

	t.Run("test blank mode oauth secret", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
			"--" + modeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither oauth-secret (command line flag) nor VC_OAUTH_SECRET")
	})

	t.Run("test blank oauth clients file path", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + kmsTypeFlagName, "web",
			"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
			"--" + databaseURLFlagName, mongoDBConnString,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMongoDBOption,
			"--" + contextEnableRemoteFlagName, "true",
			"--" + oAuthSecretFlagName, "secret",
			"--" + oAuthClientsFilePathFlagName, "",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "oauth-client-file-path value is empty")
	})

	t.Run("invalid mode", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + oAuthSecretFlagName, "test",
			"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMongoDBOption, "--" + modeFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported mode")
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Neither host-url (command line flag) nor VC_REST_HOST_URL (environment variable) have been set.")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd()

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "VC_REST_HOST_URL value is empty")
	})
}

type mockServer struct{}

func (s *mockServer) ListenAndServe() error {
	return nil
}

func (s *mockServer) ListenAndServeTLS(certFile, keyFile string) error {
	return nil
}

func TestStartCmdValidArgs(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	file, err := os.CreateTemp("", "prefix")
	require.NoError(t, err)
	_, err = file.Write([]byte("{}"))
	require.NoError(t, err)

	oauthClientsFile, err := os.CreateTemp("", "clients")
	require.NoError(t, err)
	_, err = oauthClientsFile.Write([]byte("[]"))
	require.NoError(t, err)

	defer func() {
		os.Remove(file.Name())
		os.Remove(oauthClientsFile.Name())
	}()

	startCmd := GetStartCmd(WithHTTPServer(&mockServer{}))

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + oAuthSecretFlagName, "secret",
		"--" + kmsTypeFlagName, "web",
		"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMongoDBOption, "--" + tokenFlagName, "tk1",
		"--" + requestTokensFlagName, "token1=tk1", "--" + requestTokensFlagName, "token2=tk2",
		"--" + requestTokensFlagName, "token2=tk2=1", "--" + common.LogLevelFlagName, log.ERROR.String(),
		"--" + contextEnableRemoteFlagName, "true",
		"--" + profilePathFlag, file.Name(),
		"--" + oAuthClientsFilePathFlagName, oauthClientsFile.Name(),
		"--" + databaseURLFlagName, mongoDBConnString,
		"--" + devModeFlagName, "true",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdWithEchoHandler(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	file, err := os.CreateTemp("", "prefix")
	require.NoError(t, err)
	_, err = file.Write([]byte("{}"))
	require.NoError(t, err)

	defer func() { os.Remove(file.Name()) }()

	startCmd := GetStartCmd(WithHTTPServer(&mockServer{}))

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + oAuthSecretFlagName, "secret",
		"--" + databaseTypeFlagName, databaseTypeMongoDBOption,
		"--" + databaseURLFlagName, mongoDBConnString,
		"--" + databasePrefixFlagName, "vc_rest_echo_",
		"--" + kmsTypeFlagName, "web",
		"--" + profilePathFlag, file.Name(),
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	file, err := os.CreateTemp("", "prefix")
	require.NoError(t, err)
	_, err = file.Write([]byte("{}"))
	require.NoError(t, err)

	defer func() { os.Remove(file.Name()) }()

	startCmd := GetStartCmd(WithHTTPServer(&mockServer{}))

	setEnvVars(t, databaseTypeMongoDBOption, file.Name())

	defer unsetEnvVars(t)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestCreateProviders(t *testing.T) {
	t.Run("test error from create new mongodb", func(t *testing.T) {
		cfg, err := prepareConfiguration(&startupParameters{
			dbParameters: &dbParameters{
				databaseType: databaseTypeMongoDBOption,
			},
			tlsParameters: &tlsParameters{systemCertPool: false},
		})

		require.Nil(t, cfg)
		require.Contains(t, err.Error(), "failed to create a new MongoDB client: error parsing uri: scheme must "+
			`be "mongodb" or "mongodb+srv"`)
	})
	t.Run("test invalid database type", func(t *testing.T) {
		cfg, err := prepareConfiguration(&startupParameters{
			dbParameters:  &dbParameters{databaseType: "data1"},
			tlsParameters: &tlsParameters{systemCertPool: false},
		})

		require.Nil(t, cfg)
		require.Contains(t, err.Error(), "data1 is not a valid database type. "+
			"run start --help to see the available options")
	})
}

func TestCreateVDRI(t *testing.T) {
	t.Run("test error from create new universal resolver vdr", func(t *testing.T) {
		v, err := createVDRI("wrong", "", &tls.Config{MinVersion: tls.VersionTLS12})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdr")
		require.Nil(t, v)
	})

	t.Run("test error from create new universal resolver vdr", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)
		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		cfg, err := prepareConfiguration(&startupParameters{
			universalResolverURL: "wrong",
			dbParameters: &dbParameters{
				databaseType: databaseTypeMongoDBOption,
				databaseURL:  mongoDBConnString,
			},
			tlsParameters: &tlsParameters{
				systemCertPool: false,
			},
		})

		require.Nil(t, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdr")
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createVDRI("localhost:8083", "", &tls.Config{MinVersion: tls.VersionTLS12})
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
	startCmd := GetStartCmd()

	setEnvVars(t, databaseTypeMongoDBOption, "")

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
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

func TestContextEnableRemoteInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd()

	setEnvVars(t, databaseTypeMongoDBOption, "")

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(contextEnableRemoteEnvKey, "not bool"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestDidWeb(t *testing.T) {
	v := webVDR{}

	_, err := v.Read("")
	require.Error(t, err)
}

func setEnvVars(t *testing.T, databaseType, filePath string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(oAuthSecretFlagEnvKey, "totally-secret-value")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseType)
	require.NoError(t, err)

	err = os.Setenv(databaseURLEnvKey, mongoDBConnString)
	require.NoError(t, err)

	err = os.Setenv(kmsTypeEnvKey, "web")
	require.NoError(t, err)

	err = os.Setenv(profilePathEnv, filePath)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsSecretsDatabasePrefixEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(profilePathEnv)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27018"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB() error {
	var err error

	tM := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistryBuilder().RegisterTypeMapEntry(bsontype.EmbeddedDocument, tM).Build()
	clientOpts := options.Client().SetRegistry(reg).ApplyURI(mongoDBConnString)

	mongoClient, err := mongo.NewClient(clientOpts)
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	db := mongoClient.Database("test")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}
