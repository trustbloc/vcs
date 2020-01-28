/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net/http"

	"github.com/trustbloc/edv/pkg/client/edv"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	cmdutils "github.com/trustbloc/edge-service/pkg/utils/cmd"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "VC_REST_HOST_URL"
	edvURLFlagName       = "edv-url"
	edvURLFlagShorthand  = "e"
	edvURLFlagUsage      = "URL EDV instance is running on. Format: HostName:Port."
	edvURLEnvKey         = "EDV_REST_HOST_URL"
)

var errMissingHostURL = errors.New("host URL not provided")
var errMissingEDVHostURL = errors.New("edv host URL not provided")

type vcRestParameters struct {
	srv     server
	hostURL string
	edvURL  string
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
		Short: "Start vc-rest",
		Long:  "Start vc-rest inside the edge-service",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey)
			if err != nil {
				return err
			}
			edvURL, err := cmdutils.GetUserSetVar(cmd, edvURLFlagName, edvURLEnvKey)
			if err != nil {
				return err
			}
			parameters := &vcRestParameters{
				srv:     srv,
				hostURL: hostURL,
				edvURL:  edvURL,
			}
			return startEdgeService(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(edvURLFlagName, edvURLFlagShorthand, "", edvURLFlagUsage)
}

func startEdgeService(parameters *vcRestParameters) error {
	if parameters.hostURL == "" {
		return errMissingHostURL
	}

	if parameters.edvURL == "" {
		return errMissingEDVHostURL
	}

	vcService, err := operation.New(memstore.NewProvider(), edv.New(parameters.edvURL))
	if err != nil {
		return err
	}

	handlers := vcService.GetRESTHandlers()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	log.Infof("Starting vc rest server on host %s", parameters.hostURL)

	return parameters.srv.ListenAndServe(parameters.hostURL, router)
}
