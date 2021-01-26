/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the vault instance on. Format: HostName:Port."
	hostURLEnvKey        = "VAULT_HOST_URL"
)

type serviceParameters struct {
	host string
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

	return &serviceParameters{
		host: host,
	}, err
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
}

func startService(params *serviceParameters, srv server) error {
	router := mux.NewRouter()

	service, err := vault.New(nil)
	if err != nil {
		return err
	}

	for _, handler := range service.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(params.host, cors.New(cors.Options{
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
