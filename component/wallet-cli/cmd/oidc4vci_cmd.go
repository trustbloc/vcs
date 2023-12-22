/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/henvic/httpretty"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/formatter"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vci"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
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
	demoIssuerURL              string
	vcFormat                   string
	credentialType             string
	credentialFormat           string
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
	trustRegistryURL           string
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

			if flags.credentialFormat == "" {
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

			wellKnownService := &wellknown.Service{
				HTTPClient:  httpClient,
				VDRRegistry: svc.VDR(),
			}

			provider := &oidc4vciProvider{
				storageProvider:  svc.StorageProvider(),
				httpClient:       httpClient,
				documentLoader:   svc.DocumentLoader(),
				vdrRegistry:      svc.VDR(),
				cryptoSuite:      svc.CryptoSuite(),
				wallet:           w,
				wellKnownService: wellKnownService,
			}

			var flow *oidc4vci.Flow

			opts := []oidc4vci.Opt{
				oidc4vci.WithCredentialType(flags.credentialType),
				oidc4vci.WithCredentialFormat(flags.credentialFormat),
				oidc4vci.WithClientID(flags.clientID),
				oidc4vci.WithTrustRegistryURL(flags.trustRegistryURL),
			}

			if walletInitiatedFlow {
				opts = append(opts, oidc4vci.WithIssuerState(flags.issuerState))
			} else {
				opts = append(opts, oidc4vci.WithCredentialOffer(credentialOffer))
			}

			var walletDIDIndex int

			if flags.walletDIDIndex != -1 {
				walletDIDIndex = flags.walletDIDIndex
			} else {
				walletDIDIndex = len(w.DIDs()) - 1
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

				if err = flow.Run(context.Background()); err != nil {
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

				if err = flow.Run(context.Background()); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported grant-type: %s", flags.grantType)
			}

			vc := flow.GetVC()

			var vcBytes []byte

			if vcBytes, err = json.Marshal(vc); err != nil {
				return fmt.Errorf("marshal vc: %w", err)
			}

			if err = w.Add(vcBytes); err != nil {
				return fmt.Errorf("add credential to wallet: %w", err)
			}

			var cslURL, statusListIndex, statusListType string
			if vcc := vc.Contents(); vcc.Status != nil && vcc.Status.CustomFields != nil {
				cslURL = vcc.Status.CustomFields["statusListCredential"].(string)
				statusListIndex = vcc.Status.CustomFields["statusListIndex"].(string)
				statusListType = vcc.Status.Type
			}

			slog.Info("credential added to wallet",
				"credential_id", vc.Contents().ID,
				"credential_type", strings.Join(lo.Filter(vc.Contents().Types, func(item string, i int) bool { return !strings.EqualFold(item, "VerifiableCredential") }), ","),
				"issuer_id", vc.Contents().Issuer.ID,
				"csl_url", cslURL,
				"status_list_index", statusListIndex,
				"status_list_type", statusListType,
			)

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.serviceFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.serviceFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")

	cmd.Flags().StringVar(&flags.grantType, "grant-type", "authorization_code", "supported grant types: authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code")
	cmd.Flags().StringVar(&flags.qrCodePath, "qr-code-path", "", "path to file with qr code")
	cmd.Flags().StringVar(&flags.credentialOffer, "credential-offer", "", "openid credential offer")
	cmd.Flags().StringVar(&flags.demoIssuerURL, "demo-issuer-url", "", "demo issuer url for downloading qr code automatically")
	cmd.Flags().StringVar(&flags.credentialFormat, "credential-format", "ldp_vc", "supported credential formats: ldp_vc,jwt_vc_json-ld")
	cmd.Flags().StringVar(&flags.credentialType, "credential-type", "", "credential type")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")
	cmd.Flags().StringVar(&flags.clientID, "client-id", "", "vcs oauth2 client")
	cmd.Flags().StringSliceVar(&flags.scopes, "scopes", []string{"openid"}, "vcs oauth2 scopes")
	cmd.Flags().StringVar(&flags.redirectURI, "redirect-uri", "http://127.0.0.1/callback", "callback where the authorization code should be sent")
	cmd.Flags().StringVar(&flags.userLogin, "user-login", "", "user login on issuer IdP")
	cmd.Flags().StringVar(&flags.userPassword, "user-password", "", "user password on issuer IdP")
	cmd.Flags().StringVar(&flags.issuerState, "issuer-state", "", "issuer state in wallet-initiated flow")
	cmd.Flags().StringVar(&flags.pin, "pin", "", "pin for pre-authorized code flow")
	cmd.Flags().BoolVar(&flags.enableDiscoverableClientID, "enable-discoverable-client-id", false, "enables discoverable client id scheme for dynamic client registration")
	cmd.Flags().StringVar(&flags.trustRegistryURL, "trust-registry-url", "", "if supplied, wallet will run issuer verification in trust registry")

	cmd.Flags().BoolVar(&flags.enableTracing, "enable-tracing", false, "enables http tracing")
	cmd.Flags().StringVar(&flags.proxyURL, "proxy-url", "", "proxy url for http client")

	return cmd
}

type oidc4vciProvider struct {
	storageProvider  storageapi.Provider
	httpClient       *http.Client
	documentLoader   ld.DocumentLoader
	vdrRegistry      vdrapi.Registry
	cryptoSuite      api.Suite
	wallet           *wallet.Wallet
	wellKnownService *wellknown.Service
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

func (p *oidc4vciProvider) Wallet() *wallet.Wallet {
	return p.wallet
}

func (p *oidc4vciProvider) WellKnownService() *wellknown.Service {
	return p.wellKnownService
}
