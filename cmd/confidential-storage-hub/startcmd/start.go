/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/edge-service/cmd/common"
	"github.com/trustbloc/edge-service/pkg/restapi/csh"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/healthcheck"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the confidential storage hub instance on. Format: HostName:Port."
	hostURLEnvKey        = "CHS_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "CHS_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "CHS_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "CHS_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "CHS_TLS_SERVE_KEY"
)

var logger = log.New("confidential-storage-hub/start")

type serviceParameters struct {
	host      string
	tlsParams *tlsParameters
	dbParams  *common.DBParameters
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type server interface {
	ListenAndServe(host string, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile == "" || keyFile == "" {
		return http.ListenAndServe(host, router)
	}

	return http.ListenAndServeTLS(host, certFile, keyFile, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	cmd := createStartCmd(srv)

	createFlags(cmd)

	return cmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Starts a confidential-storage-hub server",
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := getParameters(cmd)
			if err != nil {
				return err
			}

			return startService(params, srv)
		},
	}
}

func getParameters(cmd *cobra.Command) (*serviceParameters, error) {
	host, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := common.DBParams(cmd)
	if err != nil {
		return nil, err
	}

	return &serviceParameters{
		host:      host,
		tlsParams: tlsParams,
		dbParams:  dbParams,
	}, err
}

func createFlags(cmd *cobra.Command) {
	common.Flags(cmd)
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	cmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	cmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func startService(params *serviceParameters, srv server) error {
	router := mux.NewRouter()

	edgeStorage, err := common.InitEdgeStore(params.dbParams, logger)
	if err != nil {
		return fmt.Errorf("failed to init edge store: %w", err)
	}

	ariesConfig, err := newAriesConfig(params.dbParams)
	if err != nil {
		return fmt.Errorf("failed to init aries config: %w", err)
	}

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	service, err := csh.New(&operation.Config{
		StoreProvider: edgeStorage,
		Aries:         ariesConfig,
		HTTPClient:    &http.Client{},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize confidential storage hub operations: %w", err)
	}

	for _, handler := range service.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("starting server on host: %s", params.host)

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(
		params.host,
		params.tlsParams.serveCertPath,
		params.tlsParams.serveKeyPath,
		cors.New(cors.Options{
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
			},
			AllowedHeaders: []string{
				"Origin",
				"Accept",
				"Content-Type",
				"X-Requested-With",
				"Authorization",
			},
		},
		).Handler(router))
}

// TODO make KMS and crypto configurable: https://github.com/trustbloc/edge-service/issues/578
func newAriesConfig(params *common.DBParameters) (*operation.AriesConfig, error) {
	store, err := common.InitAriesStore(params, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to init aries store: %w", err)
	}

	k, err := localkms.New(
		"local-lock://custom/primary/key/",
		&kmsProvider{
			sp: store,
			sl: &noop.NoLock{},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init local kms: %w", err)
	}

	c, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("failed to init tink crypto: %w", err)
	}

	return &operation.AriesConfig{
		KMS:    k,
		Crypto: c,
	}, nil
}

type kmsProvider struct {
	sp ariesstorage.Provider
	sl secretlock.Service
}

func (k *kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.sp
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.sl
}
