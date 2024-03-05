/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"net/http"
	"net/url"
	"strings"

	"github.com/henvic/httpretty"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/formatter"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vp"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
)

type oidc4vpCommandFlags struct {
	serviceFlags                   *walletFlags
	qrCodePath                     string
	authorizationRequestURI        string
	walletDIDIndex                 int
	enableLinkedDomainVerification bool
	enableTracing                  bool
	disableDomainMatching          bool
	trustRegistryHost              string
	attestationURL                 string
	proxyURL                       string
}

// NewOIDC4VPCommand returns a new command for running OIDC4VP flow.
func NewOIDC4VPCommand() *cobra.Command {
	flags := &oidc4vpCommandFlags{
		serviceFlags: &walletFlags{},
	}

	cmd := &cobra.Command{
		Use:   "oidc4vp",
		Short: "presents credential using OIDC4VP flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, svc, err := initWallet(flags.serviceFlags)
			if err != nil {
				return fmt.Errorf("init wallet: %w", err)
			}

			httpTransport := &http.Transport{
				TLSClientConfig: svc.TLSConfig(),
			}

			if flags.proxyURL != "" {
				proxyURL, parseErr := url.Parse(flags.proxyURL)
				if parseErr != nil {
					return fmt.Errorf("parse proxy url: %w", parseErr)
				}

				httpTransport.Proxy = http.ProxyURL(proxyURL)
			}

			httpClient := &http.Client{
				Transport: httpTransport,
			}

			if flags.enableTracing {
				httpLogger := &httpretty.Logger{
					RequestHeader:   true,
					RequestBody:     true,
					ResponseHeader:  true,
					ResponseBody:    true,
					SkipSanitize:    true,
					Colors:          true,
					SkipRequestInfo: true,
					Formatters:      []httpretty.Formatter{&httpretty.JSONFormatter{}, &formatter.JWTFormatter{}},
					MaxResponseBody: 1e+7,
				}

				httpClient.Transport = httpLogger.RoundTripper(httpClient.Transport)
			}

			var walletDIDIndex int

			if flags.walletDIDIndex != -1 {
				walletDIDIndex = flags.walletDIDIndex
			} else {
				walletDIDIndex = len(w.DIDs()) - 1
			}

			attestationService, err := attestation.NewService(
				&attestationProvider{
					storageProvider: svc.StorageProvider(),
					httpClient:      httpClient,
					documentLoader:  svc.DocumentLoader(),
					cryptoSuite:     svc.CryptoSuite(),
					wallet:          w,
				},
				flags.attestationURL,
				walletDIDIndex,
			)
			if err != nil {
				return fmt.Errorf("create attestation service: %w", err)
			}

			provider := &oidc4vpProvider{
				storageProvider:    svc.StorageProvider(),
				httpClient:         httpClient,
				documentLoader:     svc.DocumentLoader(),
				vdrRegistry:        svc.VDR(),
				cryptoSuite:        svc.CryptoSuite(),
				attestationService: attestationService,
				wallet:             w,
			}

			if flags.trustRegistryHost != "" {
				provider.trustRegistry = trustregistry.NewClient(httpClient, flags.trustRegistryHost)
			}

			var authorizationRequest string

			if flags.authorizationRequestURI != "" {
				authorizationRequest = flags.authorizationRequestURI
			} else if flags.qrCodePath != "" {
				authorizationRequest, err = readQRCode(flags.qrCodePath)
				if err != nil {
					return fmt.Errorf("read qr code: %v", err)
				}
			} else {
				return fmt.Errorf("either --qr-code-path or --authorization-request-uri flag must be set")
			}

			requestURI := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

			var flow *oidc4vp.Flow

			opts := []oidc4vp.Opt{
				oidc4vp.WithRequestURI(requestURI),
				oidc4vp.WithWalletDIDIndex(walletDIDIndex),
			}

			if flags.enableLinkedDomainVerification {
				opts = append(opts, oidc4vp.WithLinkedDomainVerification())
			}

			if flags.disableDomainMatching {
				opts = append(opts, oidc4vp.WithDomainMatchingDisabled())
			}

			if flow, err = oidc4vp.NewFlow(provider, opts...); err != nil {
				return err
			}

			if err = flow.Run(context.Background()); err != nil {
				return err
			}

			return nil
		},
	}

	createFlags(cmd, flags)

	return cmd
}

func createFlags(cmd *cobra.Command, flags *oidc4vpCommandFlags) {
	cmd.Flags().StringVar(&flags.serviceFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.serviceFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")

	cmd.Flags().StringVar(&flags.qrCodePath, "qr-code-path", "", "path to file with qr code")
	cmd.Flags().StringVar(&flags.authorizationRequestURI, "authorization-request-uri", "", "authorization request uri, starts with 'openid-vc://?request_uri=' prefix")
	cmd.Flags().BoolVar(&flags.enableLinkedDomainVerification, "enable-linked-domain-verification", false, "enables linked domain verification")
	cmd.Flags().BoolVar(&flags.disableDomainMatching, "disable-domain-matching", false, "disables domain matching for issuer and verifier when presenting credentials (only for did:web)")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")
	cmd.Flags().StringVar(&flags.attestationURL, "attestation-url", "", "attestation url, i.e. https://<host>/vcs/wallet/attestation")
	cmd.Flags().StringVar(&flags.trustRegistryHost, "trust-registry-host", "", "trust registry host, i.e. https://<host>/trustregistry")

	cmd.Flags().BoolVar(&flags.enableTracing, "enable-tracing", false, "enables http tracing")
	cmd.Flags().StringVar(&flags.proxyURL, "proxy-url", "", "proxy url for http client")
}

type oidc4vpProvider struct {
	storageProvider    storageapi.Provider
	httpClient         *http.Client
	documentLoader     ld.DocumentLoader
	vdrRegistry        vdrapi.Registry
	cryptoSuite        api.Suite
	attestationService *attestation.Service
	trustRegistry      *trustregistry.Client
	wallet             *wallet.Wallet
}

func (p *oidc4vpProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vpProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vpProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vpProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vpProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vpProvider) AttestationService() oidc4vp.AttestationService {
	return p.attestationService
}

func (p *oidc4vpProvider) TrustRegistry() oidc4vp.TrustRegistry {
	return p.trustRegistry
}

func (p *oidc4vpProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
