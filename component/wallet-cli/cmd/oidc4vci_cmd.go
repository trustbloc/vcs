/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/henvic/httpretty"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/formatter"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vci"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

const (
	authorizationCodeGrantType = "authorization_code"
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

type oidc4vciCommandFlags struct {
	serviceFlags               *walletFlags
	grantType                  string
	qrCodePath                 string
	credentialOffer            string
	proofType                  string
	demoIssuerURL              string
	vcFormat                   string
	credentialType             string
	oidcCredentialFormat       vcsverifiable.OIDCFormat
	walletDIDIndex             int
	clientID                   string
	scopes                     []string
	redirectURI                string
	userLogin                  string
	userPassword               string
	issuerState                string
	pin                        string
	enableDiscoverableClientID bool
	enableTracing              bool
	proxyURL                   string
	trustRegistryHost          string
	attestationURL             string
}

func NewOIDC4VCICommand() *cobra.Command {
	flags := &oidc4vciCommandFlags{
		serviceFlags: &walletFlags{},
	}

	cmd := &cobra.Command{
		Use:   "oidc4vci",
		Short: "requests credential with OIDC4VCI authorization or pre-authorized code flows",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, svc, err := initWallet(flags.serviceFlags)
			if err != nil {
				return fmt.Errorf("init wallet: %w", err)
			}

			emptyCredentialOffer := flags.credentialOffer == "" && flags.qrCodePath == "" && flags.demoIssuerURL == ""
			walletInitiatedFlow := flags.issuerState != ""

			if emptyCredentialOffer && !walletInitiatedFlow {
				return fmt.Errorf("set --qr-code-path or --credential-offer or --demo-issuer-url " +
					"to retrieve credential offer")
			}

			if !emptyCredentialOffer && walletInitiatedFlow {
				slog.Error("set either --issuer-state for wallet-initiated flow or one of --qr-code-path or " +
					"--credential-offer or --demo-issuer-url to retrieve credential offer")
			}

			if flags.credentialType == "" {
				return fmt.Errorf("--credential-type not set")
			}

			if flags.oidcCredentialFormat == "" {
				return fmt.Errorf("--credential-format not set")
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

			cookie, err := cookiejar.New(&cookiejar.Options{})
			if err != nil {
				return fmt.Errorf("init cookie jar: %w", err)
			}

			httpClient := &http.Client{
				Jar:       cookie,
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

			if flags.demoIssuerURL != "" {
				var offer *parsedCredentialOffer

				offer, err = fetchCredentialOffer(flags.demoIssuerURL, httpClient)
				if err != nil {
					return fmt.Errorf("fetch credential offer from %s: %w", flags.demoIssuerURL, err)
				}

				flags.pin = offer.Pin
				flags.credentialOffer = offer.CredentialOfferURL
			}

			var credentialOffer string

			if flags.credentialOffer != "" {
				credentialOffer = flags.credentialOffer
			} else if flags.qrCodePath != "" {
				credentialOffer, err = readQRCode(flags.qrCodePath)
				if err != nil {
					return fmt.Errorf("read qr code: %w", err)
				}
			}

			var walletDIDIndex int

			if flags.walletDIDIndex != -1 {
				walletDIDIndex = flags.walletDIDIndex
			} else {
				walletDIDIndex = len(w.DIDs()) - 1
			}

			attestationService, err := attestation.NewService(
				&attestationServiceProvider{
					storageProvider: svc.StorageProvider(),
					httpClient:      httpClient,
					documentLoader:  svc.DocumentLoader(),
					cryptoSuite:     svc.CryptoSuite(),
				},
				flags.attestationURL,
				w.DIDs()[walletDIDIndex],
				w.SignatureType(),
			)
			if err != nil {
				return fmt.Errorf("create attestation service: %w", err)
			}

			wellKnownService := &wellknown.Service{
				HTTPClient:  httpClient,
				VDRRegistry: svc.VDR(),
			}

			provider := &oidc4vciProvider{
				storageProvider:    svc.StorageProvider(),
				httpClient:         httpClient,
				documentLoader:     svc.DocumentLoader(),
				vdrRegistry:        svc.VDR(),
				cryptoSuite:        svc.CryptoSuite(),
				attestationService: attestationService,
				wallet:             w,
				wellKnownService:   wellKnownService,
			}

			if flags.trustRegistryHost != "" {
				provider.trustRegistry = trustregistry.NewClient(httpClient, flags.trustRegistryHost)
			}

			var flow *oidc4vci.Flow

			opts := []oidc4vci.Opt{
				oidc4vci.WithCredentialType(flags.credentialType),
				oidc4vci.WithOIDCCredentialFormat(flags.oidcCredentialFormat),
				oidc4vci.WithClientID(flags.clientID),
			}

			if walletInitiatedFlow {
				opts = append(opts, oidc4vci.WithIssuerState(flags.issuerState))
			} else {
				opts = append(opts, oidc4vci.WithCredentialOffer(credentialOffer))
			}

			if flags.proofType == "cwt" {
				opts = append(opts, oidc4vci.WithProofBuilder(
					oidc4vci.NewCWTProofBuilder(),
				))
			}

			opts = append(opts, oidc4vci.WithWalletDIDIndex(walletDIDIndex))

			switch flags.grantType {
			case authorizationCodeGrantType:
				if flags.clientID == "" {
					return fmt.Errorf("--client-id not set")
				}

				if flags.redirectURI == "" {
					return fmt.Errorf("--redirect-uri not set")
				}

				if len(flags.scopes) == 0 {
					return fmt.Errorf("--scopes not set")
				}

				opts = append(opts,
					oidc4vci.WithScopes(flags.scopes),
					oidc4vci.WithRedirectURI(flags.redirectURI),
					oidc4vci.WithUserLogin(flags.userLogin),
					oidc4vci.WithUserPassword(flags.userPassword),
				)

				if walletInitiatedFlow {
					opts = append(opts, oidc4vci.WithFlowType(oidc4vci.FlowTypeWalletInitiated))
				} else {
					opts = append(opts, oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode))
				}

				if flags.enableDiscoverableClientID {
					opts = append(opts, oidc4vci.WithEnableDiscoverableClientID())
				}

				if flow, err = oidc4vci.NewFlow(provider, opts...); err != nil {
					return err
				}

				if _, err = flow.Run(context.Background()); err != nil {
					return err
				}
			case preAuthorizedCodeGrantType:
				opts = append(opts,
					oidc4vci.WithFlowType(oidc4vci.FlowTypePreAuthorizedCode),
					oidc4vci.WithPin(flags.pin),
				)

				if flow, err = oidc4vci.NewFlow(provider, opts...); err != nil {
					return err
				}

				if _, err = flow.Run(context.Background()); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported grant-type: %s", flags.grantType)
			}

			return nil
		},
	}

	var oidcCredentialFormat string

	cmd.Flags().StringVar(&flags.serviceFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.serviceFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")

	cmd.Flags().StringVar(&flags.grantType, "grant-type", "authorization_code", "supported grant types: authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code")
	cmd.Flags().StringVar(&flags.qrCodePath, "qr-code-path", "", "path to file with qr code")
	cmd.Flags().StringVar(&flags.credentialOffer, "credential-offer", "", "openid credential offer")
	cmd.Flags().StringVar(&flags.demoIssuerURL, "demo-issuer-url", "", "demo issuer url for downloading qr code automatically")
	cmd.Flags().StringVar(&oidcCredentialFormat, "credential-format", "ldp_vc", "supported credential formats: ldp_vc,jwt_vc_json-ld")
	cmd.Flags().StringVar(&flags.credentialType, "credential-type", "", "credential type")
	cmd.Flags().StringVar(&flags.proofType, "proof-type", "", "proof-type. jwt or cwt. default jwt")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")
	cmd.Flags().StringVar(&flags.clientID, "client-id", "", "vcs oauth2 client")
	cmd.Flags().StringSliceVar(&flags.scopes, "scopes", []string{"openid"}, "vcs oauth2 scopes")
	cmd.Flags().StringVar(&flags.redirectURI, "redirect-uri", "http://127.0.0.1/callback", "callback where the authorization code should be sent")
	cmd.Flags().StringVar(&flags.userLogin, "user-login", "", "user login on issuer IdP")
	cmd.Flags().StringVar(&flags.userPassword, "user-password", "", "user password on issuer IdP")
	cmd.Flags().StringVar(&flags.issuerState, "issuer-state", "", "issuer state in wallet-initiated flow")
	cmd.Flags().StringVar(&flags.pin, "pin", "", "pin for pre-authorized code flow")
	cmd.Flags().BoolVar(&flags.enableDiscoverableClientID, "enable-discoverable-client-id", false, "enables discoverable client id scheme for dynamic client registration")
	cmd.Flags().StringVar(&flags.attestationURL, "attestation-url", "", "attestation url with profile id and profile version, i.e. <host>/profiles/{profileID}/{profileVersion}/wallet/attestation")
	cmd.Flags().StringVar(&flags.trustRegistryHost, "trust-registry-host", "", "<trust-registry-host>/wallet/interactions/issuance to validate that the issuer is trusted according to policy")

	cmd.Flags().BoolVar(&flags.enableTracing, "enable-tracing", false, "enables http tracing")
	cmd.Flags().StringVar(&flags.proxyURL, "proxy-url", "", "proxy url for http client")

	flags.oidcCredentialFormat = vcsverifiable.OIDCFormat(oidcCredentialFormat)

	return cmd
}

type oidc4vciProvider struct {
	storageProvider    storageapi.Provider
	httpClient         *http.Client
	documentLoader     ld.DocumentLoader
	vdrRegistry        vdrapi.Registry
	cryptoSuite        api.Suite
	attestationService *attestation.Service
	trustRegistry      *trustregistry.Client
	wallet             *wallet.Wallet
	wellKnownService   *wellknown.Service
}

func (p *oidc4vciProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vciProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vciProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vciProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vciProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vciProvider) AttestationService() oidc4vci.AttestationService {
	return p.attestationService
}

func (p *oidc4vciProvider) TrustRegistry() oidc4vci.TrustRegistry {
	return p.trustRegistry
}

func (p *oidc4vciProvider) Wallet() *wallet.Wallet {
	return p.wallet
}

func (p *oidc4vciProvider) WellKnownService() *wellknown.Service {
	return p.wellKnownService
}
