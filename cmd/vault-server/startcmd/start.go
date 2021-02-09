/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/healthcheck"
	"github.com/trustbloc/edge-service/pkg/restapi/vault/operation"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the vault instance on. Format: HostName:Port."
	hostURLEnvKey        = "VAULT_HOST_URL"

	remoteKMSURLFlagName  = "remote-kms-url"
	remoteKMSURLFlagUsage = "Remote KMS URL."
	remoteKMSURLEnvKey    = "VAULT_REMOTE_KMS_URL"

	edvURLFlagName  = "edv-url"
	edvURLFlagUsage = "EDV URL."
	edvURLEnvKey    = "VAULT_EDV_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "VAULT_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "VAULT_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "VAULT_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "VAULT_TLS_SERVE_KEY"
)

type serviceParameters struct {
	host         string
	remoteKMSURL string
	edvURL       string
	tlsParams    *tlsParameters
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
		Short: "Starts a vault server",
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

	remoteKMSURL, err := cmdutils.GetUserSetVarFromString(cmd, remoteKMSURLFlagName, remoteKMSURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	edvURL, err := cmdutils.GetUserSetVarFromString(cmd, edvURLFlagName, edvURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	return &serviceParameters{
		host:         host,
		remoteKMSURL: remoteKMSURL,
		edvURL:       edvURL,
		tlsParams:    tlsParams,
	}, err
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

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(remoteKMSURLFlagName, "", "", remoteKMSURLFlagUsage)
	cmd.Flags().StringP(edvURLFlagName, "", "", edvURLFlagUsage)
	cmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	cmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	cmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
}

const (
	keystorePrimaryKeyURI = "local-lock://keystorekms"
)

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

func startService(params *serviceParameters, srv server) error { // nolint: funlen
	rootCAs, err := tlsutils.GetCertPool(params.tlsParams.systemCertPool, params.tlsParams.caCerts)
	if err != nil {
		return err
	}

	DB := mem.NewProvider()

	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		// TODO: make a storage configurable
		storageProvider: DB,
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return fmt.Errorf("localkms new: %w", err)
	}

	vaultClient, err := vault.NewClient(
		params.remoteKMSURL,
		params.edvURL,
		keyManager,
		DB,
		vault.WithHTTPClient(&http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    rootCAs,
					MinVersion: tls.VersionTLS12,
				},
			},
		}),
	)
	if err != nil {
		return fmt.Errorf("vault new client: %w", err)
	}

	service := operation.New(vaultClient)
	handlers := service.GetRESTHandlers()

	// add health check endpoint
	healthCheckService := healthcheck.New()
	handlers = append(handlers, healthCheckService.GetOperations()...)

	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(params.host,
		params.tlsParams.serveCertPath,
		params.tlsParams.serveKeyPath,
		cors.New(cors.Options{
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodDelete,
			},
			AllowedHeaders: []string{
				"Origin",
				"Accept",
				"Content-Type",
				"X-Requested-With",
				"Authorization",
			},
		}).Handler(router))
}
