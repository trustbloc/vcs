/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edv/pkg/client/edv"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"

	"github.com/trustbloc/edge-service/pkg/restapi/vc"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	cmdutils "github.com/trustbloc/edge-service/pkg/utils/cmd"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the vc-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "VC_REST_HOST_URL"

	edvURLFlagName      = "edv-url"
	edvURLFlagShorthand = "e"
	edvURLFlagUsage     = "URL EDV instance is running on. Format: HostName:Port."
	edvURLEnvKey        = "EDV_REST_HOST_URL"

	blocDomainFlagName      = "bloc-domain"
	blocDomainFlagShorthand = "b"
	blocDomainFlagUsage     = "Bloc domain"
	blocDomainEnvKey        = "BLOC_DOMAIN"

	hostURLExternalFlagName      = "host-url-external"
	hostURLExternalFlagShorthand = "x"
	hostURLExternalEnvKey        = "VC_REST_HOST_URL_EXTERNAL"
	hostURLExternalFlagUsage     = "Host External Name:Port This is the URL for the host server as seen externally." +
		" If not provided, then the host url will be used here." +
		" Alternatively, this can be set with the following environment variable: " + hostURLExternalEnvKey

	universalResolverURLFlagName      = "universal-resolver-url"
	universalResolverURLFlagShorthand = "r"
	universalResolverURLFlagUsage     = "Universal Resolver instance is running on. Format: HostName:Port."
	universalResolverURLEnvKey        = "UNIVERSAL_RESOLVER_HOST_URL"

	modeFlagName      = "mode"
	modeFlagShorthand = "m"
	modeFlagUsage     = "Mode in which the vc-rest service will run. Possible values: " +
		"['issuer', 'verifier'] (default: issuer)."
	modeEnvKey = "VC_REST_MODE"

	didMethodVeres = "v1"
)

// mode in which to run the vc-rest service
type mode string

const (
	verifier mode = "verifier"
	issuer   mode = "issuer"
)

type vcRestParameters struct {
	hostURL              string
	edvURL               string
	blocDomain           string
	hostURLExternal      string
	universalResolverURL string
	mode                 string
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
			parameters, err := getVCRestParameters(cmd)
			if err != nil {
				return err
			}

			return startEdgeService(parameters, srv)
		},
	}
}

func getVCRestParameters(cmd *cobra.Command) (*vcRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	edvURL, err := cmdutils.GetUserSetVar(cmd, edvURLFlagName, edvURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	blocDomain, err := cmdutils.GetUserSetVar(cmd, blocDomainFlagName, blocDomainEnvKey, false)
	if err != nil {
		return nil, err
	}

	hostURLExternal, err := cmdutils.GetUserSetVar(cmd, hostURLExternalFlagName,
		hostURLExternalEnvKey, true)
	if err != nil {
		return nil, err
	}

	universalResolverURL, err := cmdutils.GetUserSetVar(cmd, universalResolverURLFlagName,
		universalResolverURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	mode, err := cmdutils.GetUserSetVar(cmd, modeFlagName, modeEnvKey, true)
	if err != nil {
		return nil, err
	}

	if !supportedMode(mode) {
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}

	if mode == "" {
		mode = string(issuer)
	}

	return &vcRestParameters{
		hostURL:              hostURL,
		edvURL:               edvURL,
		blocDomain:           blocDomain,
		hostURLExternal:      hostURLExternal,
		universalResolverURL: universalResolverURL,
		mode:                 mode,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(edvURLFlagName, edvURLFlagShorthand, "", edvURLFlagUsage)
	startCmd.Flags().StringP(blocDomainFlagName, blocDomainFlagShorthand, "", blocDomainFlagUsage)
	startCmd.Flags().StringP(hostURLExternalFlagName, hostURLExternalFlagShorthand, "", hostURLExternalFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, modeFlagShorthand, "", modeFlagUsage)
}

func startEdgeService(parameters *vcRestParameters, srv server) error {
	// Create KMS
	kms, err := createKMS(mem.NewProvider())
	if err != nil {
		return err
	}

	// Create VDRI
	vdri, err := createVDRI(parameters.universalResolverURL, kms)
	if err != nil {
		return err
	}

	externalHostURL := parameters.hostURL
	if parameters.hostURLExternal != "" {
		externalHostURL = parameters.hostURLExternal
	}

	vcService, err := vc.New(&operation.Config{StoreProvider: memstore.NewProvider(),
		EDVClient: edv.New(parameters.edvURL), KMS: kms, VDRI: vdri, HostURL: externalHostURL,
		Mode: parameters.mode, Domain: parameters.blocDomain})
	if err != nil {
		return err
	}

	handlers := vcService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	log.Infof("Starting vc rest server on host %s", parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, router)
}

func createKMS(s storage.Provider) (ariesapi.CloseableKMS, error) {
	kmsProvider, err := context.New(context.WithStorageProvider(s))
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms provider: %w", err)
	}

	kms, err := legacykms.New(kmsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms: %w", err)
	}

	return kms, nil
}

func createVDRI(universalResolver string, kms legacykms.KMS) (vdriapi.Registry, error) {
	var opts []vdripkg.Option

	var blocVDRIOpts []trustbloc.Option

	if universalResolver != "" {
		universalResolverVDRI, err := httpbinding.New(universalResolver,
			httpbinding.WithAccept(func(method string) bool { return method == didMethodVeres }))
		if err != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", err)
		}

		// add universal resolver vdri
		opts = append(opts, vdripkg.WithVDRI(universalResolverVDRI))

		// add universal resolver to bloc vdri
		blocVDRIOpts = append(blocVDRIOpts, trustbloc.WithResolverURL(universalResolver))
	}

	// add bloc vdri
	opts = append(opts, vdripkg.WithVDRI(trustbloc.New(blocVDRIOpts...)))

	vdriProvider, err := context.New(context.WithLegacyKMS(kms))
	if err != nil {
		return nil, fmt.Errorf("failed to create new vdri provider: %w", err)
	}

	return vdripkg.New(vdriProvider, opts...), nil
}

func supportedMode(mode string) bool {
	if len(mode) > 0 && mode != string(verifier) && mode != string(issuer) {
		return false
	}

	return true
}
