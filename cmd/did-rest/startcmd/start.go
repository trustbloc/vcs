/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/key"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/edge-service/cmd/common"
	"github.com/trustbloc/edge-service/pkg/proxy/rules/filerules"
	"github.com/trustbloc/edge-service/pkg/restapi/did"
	"github.com/trustbloc/edge-service/pkg/restapi/did/operation"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "DID_REST_HOST_URL"

	configFlagName      = "config-file"
	configFlagShorthand = "f"
	configFlagUsage     = "Path to configuration file with proxy rules."
	configEnvKey        = "DID_REST_CONFIG_FILE"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "DID_REST_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "DID_REST_TLS_CACERTS"
)

const (

	// api
	healthCheckEndpoint = "/healthcheck"
)

var logger = log.New("did-rest")

type didRestParameters struct {
	hostURL           string
	configFile        string
	tlsSystemCertPool bool
	tlsCACerts        []string
	logLevel          string
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start did-rest",
		Long:  "Start did-rest inside the edge-service",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getDIDRestParameters(cmd)
			if err != nil {
				return err
			}

			return startDidService(parameters, srv)
		},
	}
}

func getDIDRestParameters(cmd *cobra.Command) (*didRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	configFile, err := cmdutils.GetUserSetVarFromString(cmd, configFlagName, configEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &didRestParameters{
		hostURL:           hostURL,
		configFile:        configFile,
		tlsSystemCertPool: tlsSystemCertPool,
		tlsCACerts:        tlsCACerts,
		logLevel:          loggingLevel,
	}, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	return tlsSystemCertPool, tlsCACerts, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(configFlagName, configFlagShorthand, "", configFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
}

func startDidService(parameters *didRestParameters, srv server) error {
	if parameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, parameters.logLevel)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	ruleProvider, err := filerules.New(parameters.configFile)
	if err != nil {
		return err
	}

	didService := did.New(&operation.Config{
		RuleProvider: ruleProvider,
		KeyVDRI:      *key.New(),
		TLSConfig:    &tls.Config{RootCAs: rootCAs}})

	handlers := didService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	logger.Infof("Starting did rest server on host %s", parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}

func healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		logger.Errorf("healthcheck response failure, %s", err)
	}
}
