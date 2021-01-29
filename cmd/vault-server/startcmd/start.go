/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
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

	vault "github.com/trustbloc/edge-service/pkg/restapi/vault/operation"
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
)

type serviceParameters struct {
	host         string
	remoteKMSURL string
	edvURL       string
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

	remoteKMSURL, err := cmdutils.GetUserSetVarFromString(cmd, remoteKMSURLFlagName, remoteKMSURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	edvURL, err := cmdutils.GetUserSetVarFromString(cmd, edvURLFlagName, edvURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	return &serviceParameters{
		host:         host,
		remoteKMSURL: remoteKMSURL,
		edvURL:       edvURL,
	}, err
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(remoteKMSURLFlagName, "", "", remoteKMSURLFlagUsage)
	cmd.Flags().StringP(edvURLFlagName, "", "", edvURLFlagUsage)
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

func startService(params *serviceParameters, srv server) error {
	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		// TODO: make a storage configurable
		storageProvider: mem.NewProvider(),
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return fmt.Errorf("localkms new: %w", err)
	}

	service, err := vault.New(&vault.Config{
		RemoteKMSURL: params.remoteKMSURL,
		EDVURL:       params.edvURL,
		LocalKMS:     keyManager,
		HTTPClient:   &http.Client{Timeout: time.Minute},
	})
	if err != nil {
		return fmt.Errorf("vault new: %w", err)
	}

	router := mux.NewRouter()

	for _, handler := range service.GetRESTHandlers() {
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
