/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

const (
	authorizationCodeGrantType = "authorization_code"
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

type oidc4ciCommandFlags struct {
	QRCode              string
	InitiateIssuanceURL string
	DemoIssuerURL       string
	ClientID            string
	GrantType           string
	Scope               []string
	RedirectURI         string
	Login               string
	Password            string
	VCFormat            string
	VCProvider          string
	CredentialType      string
	CredentialFormat    string
	Debug               bool
	Pin                 string

	WalletUserId     string
	WalletPassPhrase string
	WalletDidKeyID   string
	WalletDidID      string

	StorageProvider           string
	StorageProviderConnString string
	InsecureTls               bool
	DidMethod                 string
	DidKeyType                string
}

func NewOIDC4CICommand() *cobra.Command {
	flags := &oidc4ciCommandFlags{}
	var contextProvider, didDomain, didServiceAuthToken, uniResolverUrl, oidcProviderUrl string

	cmd := &cobra.Command{
		Use:   "oidc4ci",
		Short: "Request vc with oidc4ci authorized or pre-authorized code flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			isPreAuthorize := flags.GrantType == preAuthorizedCodeGrantType
			if flags.QRCode == "" && flags.InitiateIssuanceURL == "" && flags.DemoIssuerURL == "" {
				return fmt.Errorf("either qr-code or initiate-issuance-url should be set")
			}

			if flags.GrantType != authorizationCodeGrantType && flags.GrantType != preAuthorizedCodeGrantType {
				return fmt.Errorf("invalid grant-type")
			}

			if flags.CredentialType == "" {
				return fmt.Errorf("missing credential-type")
			}

			if flags.CredentialFormat == "" {
				return fmt.Errorf("missing credential-format")
			}

			if !isPreAuthorize {
				if len(flags.Scope) == 0 {
					return fmt.Errorf("missing scope")
				}

				if flags.RedirectURI == "" {
					return fmt.Errorf("missing redirect-uri")
				}
			}

			var initiateIssuanceURL string

			if flags.DemoIssuerURL != "" {
				parsedUrl, pin, err := readIssuanceCodeFromIssuerUrl(flags.DemoIssuerURL, flags.InsecureTls)
				if err != nil {
					return fmt.Errorf("can not read url from demo issuer %v", err)
				}

				flags.Pin = pin
				flags.InitiateIssuanceURL = parsedUrl
			}

			if flags.InitiateIssuanceURL != "" {
				initiateIssuanceURL = flags.InitiateIssuanceURL
			} else if flags.QRCode != "" {
				var err error

				initiateIssuanceURL, err = readQRCode(flags.QRCode)
				if err != nil {
					return fmt.Errorf("read qr code: %w", err)
				}
			}

			providerOpts := []vcprovider.ConfigOption{
				func(c *vcprovider.Config) {
					c.VCFormat = flags.VCFormat
					c.Debug = flags.Debug

					if contextProvider != "" {
						c.ContextProviderURL = contextProvider
					}
					if didDomain != "" {
						c.DidDomain = didDomain
					}
					if didServiceAuthToken != "" {
						c.DidServiceAuthToken = didServiceAuthToken
					}
					if uniResolverUrl != "" {
						c.UniResolverURL = uniResolverUrl
					}
					if oidcProviderUrl != "" {
						c.OidcProviderURL = oidcProviderUrl
					}

					c.WalletUserId = flags.WalletUserId
					c.WalletPassPhrase = flags.WalletPassPhrase
					c.WalletDidKeyID = flags.WalletDidKeyID
					c.WalletDidID = flags.WalletDidID

					c.StorageProvider = flags.StorageProvider
					c.StorageProviderConnString = flags.StorageProviderConnString
					c.InsecureTls = flags.InsecureTls
					c.DidMethod = flags.DidMethod
					c.DidKeyType = flags.DidKeyType
				},
			}

			runner, err := walletrunner.New(flags.VCProvider, providerOpts...)
			if err != nil {
				return fmt.Errorf("create wallet runner: %w", err)
			}

			config := &walletrunner.OIDC4CIConfig{
				InitiateIssuanceURL: initiateIssuanceURL,
				ClientID:            flags.ClientID,
				Scope:               flags.Scope,
				RedirectURI:         flags.RedirectURI,
				Login:               flags.Login,
				Password:            flags.Password,
				CredentialType:      flags.CredentialType,
				CredentialFormat:    flags.CredentialFormat,
				Pin:                 flags.Pin,
			}

			if isPreAuthorize {
				return runner.RunOIDC4CIPreAuth(config)
			}

			return runner.RunOIDC4CI(config)
		},
	}

	cmd.Flags().StringVar(&contextProvider, "context-provider-url", "", "context provider. example: https://static-file-server.stg.trustbloc.dev/ld-contexts.json") //nolint
	cmd.Flags().StringVar(&didDomain, "did-domain", "", "did domain. example: https://orb-1.stg.trustbloc.dev")                                                     //nolint
	cmd.Flags().StringVar(&didServiceAuthToken, "did-service-auth-token", "", "did service authorization token. example: tk1")                                      //nolint
	cmd.Flags().StringVar(&uniResolverUrl, "uni-resolver-url", "", "uni resolver url. example: https://did-resolver.stg.trustbloc.dev/1.0/identifiers")             //nolint
	cmd.Flags().StringVar(&oidcProviderUrl, "oidc-provider-url", "", "oidc provider url. example: https://api-gateway.stg.trustbloc.dev")                           //nolint

	cmd.Flags().StringVar(&flags.QRCode, "qr-code", "", "path to file with QR code")
	cmd.Flags().StringVar(&flags.InitiateIssuanceURL, "initiate-issuance-url", "", "initiate issuance url")
	cmd.Flags().StringVar(&flags.DemoIssuerURL, "demo-issuer-url", "", "demo issuer url. will automatically download qrcode")
	cmd.Flags().StringVar(&flags.ClientID, "client-id", "", "oauth2 client ID")
	cmd.Flags().StringVar(&flags.GrantType, "grant-type", "authorization_code", "grant type")
	cmd.Flags().StringSliceVar(&flags.Scope, "scope", nil, "oauth2 scopes. Can be used to pass credential type")
	cmd.Flags().StringVar(&flags.RedirectURI, "redirect-uri", "", "callback where the authorization code should be sent")
	cmd.Flags().StringVar(&flags.Login, "login", "", "user login email")
	cmd.Flags().StringVar(&flags.Password, "password", "", "user login password")
	cmd.Flags().StringVar(&flags.VCFormat, "vc-format", "jwt_vc", "vc format [jwt_vc|ldp_vc]")
	cmd.Flags().StringVar(&flags.VCProvider, "vc-provider", "vcs", "vc provider")
	cmd.Flags().StringVar(&flags.CredentialType, "credential-type", "", "credential type")
	cmd.Flags().StringVar(&flags.CredentialFormat, "credential-format", "", "credential format")
	cmd.Flags().StringVar(&flags.Pin, "pin", "", "pre-authorized flow pin")
	cmd.Flags().BoolVar(&flags.Debug, "debug", false, "enable debug mode")
	cmd.Flags().BoolVar(&flags.InsecureTls, "insecure", false, "this option allows to skip the verification of ssl\\tls")

	cmd.Flags().StringVar(&flags.WalletUserId, "wallet-user-id", "", "existing wallet user id")
	cmd.Flags().StringVar(&flags.WalletPassPhrase, "wallet-passphrase", "", "existing wallet pass phrase")
	cmd.Flags().StringVar(&flags.StorageProvider, "storage-provider", "", "storage provider. supported: mem,leveldb,mongodb")
	cmd.Flags().StringVar(&flags.StorageProviderConnString, "storage-provider-connection-string", "", "storage provider connection string")

	cmd.Flags().StringVar(&flags.WalletDidID, "wallet-did", "", "existing wallet did")
	cmd.Flags().StringVar(&flags.WalletDidKeyID, "wallet-did-keyid", "", "existing wallet did key id")
	cmd.Flags().StringVar(&flags.DidMethod, "did-method", "orb", "did method, supported: orb,ion. default: orb")
	cmd.Flags().StringVar(&flags.DidKeyType, "did-key-type", "ECDSAP384DER", "did key type. default: ECDSAP384DER")

	return cmd
}

func readIssuanceCodeFromIssuerUrl(issuerUrl string, insecureSkipVerify bool) (string, string, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		},
	}
	resp, err := httpClient.Get(issuerUrl)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("invalid status code. expected 200, got %v", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	_ = resp.Body.Close()

	urlParsed := string(data)
	r := regexp.MustCompile(`(openid-initiate-issuance://\?[^<]+)`)
	urlParsed = r.FindString(urlParsed)
	urlParsed, err = url.QueryUnescape(urlParsed)
	urlParsed = strings.ReplaceAll(urlParsed, "&amp;", "&")

	pin := ""
	pinGroups := regexp.MustCompile(`<div id="pin">([^<]+)`).FindAllStringSubmatch(string(data), -1)
	if len(pinGroups) == 1 {
		if len(pinGroups[0]) == 2 {
			pin = pinGroups[0][1]
		}
	}

	return urlParsed, pin, nil
}
