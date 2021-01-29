/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator"
	"github.com/trustbloc/edge-service/pkg/restapi/healthcheck"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the comparator instance on. Format: HostName:Port."
	hostURLEnvKey        = "COMPARATOR_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "COMPARATOR_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "COMPARATOR_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "COMPARATOR_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "COMPARATOR_TLS_SERVE_KEY"
)

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type serviceParameters struct {
	host      string
	tlsParams *tlsParameters
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

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Starts a comparator server",
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

	return &serviceParameters{
		host:      host,
		tlsParams: tlsParams,
	}, err
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	cmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	cmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
}

func startService(params *serviceParameters, srv server) error {
	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	service, err := comparator.New(nil)
	if err != nil {
		return err
	}

	for _, handler := range service.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(params.host, params.tlsParams.serveCertPath, params.tlsParams.serveKeyPath,
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
