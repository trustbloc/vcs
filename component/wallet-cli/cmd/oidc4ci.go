/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"

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
	ClientID            string
	GrantType           string
	Scope               []string
	RedirectURI         string
	VCFormat            string
	VCProvider          string
	LoginURL            string
	CredentialType      string
	CredentialFormat    string
	Debug               bool
}

func NewOIDC4CICommand() *cobra.Command {
	flags := &oidc4ciCommandFlags{}

	cmd := &cobra.Command{
		Use:   "oidc4ci",
		Short: "Request vc with oidc4ci authorized or pre-authorized code flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			if flags.QRCode == "" && flags.InitiateIssuanceURL == "" {
				return fmt.Errorf("either qr-code or initiate-issuance-url should be set")
			}

			if flags.GrantType != authorizationCodeGrantType && flags.GrantType != preAuthorizedCodeGrantType {
				return fmt.Errorf("invalid grant-type")
			}

			if len(flags.Scope) == 0 {
				return fmt.Errorf("missing scope")
			}

			if flags.RedirectURI == "" {
				return fmt.Errorf("missing redirect-uri")
			}

			if flags.LoginURL == "" {
				return fmt.Errorf("missing login-url")
			}

			if flags.CredentialType == "" {
				return fmt.Errorf("missing credential-type")
			}

			if flags.CredentialFormat == "" {
				return fmt.Errorf("missing credential-format")
			}

			var initiateIssuanceURL string

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
				LoginURL:            flags.LoginURL,
				CredentialType:      flags.CredentialType,
				CredentialFormat:    flags.CredentialFormat,
				Interactive:         false,
			}

			if flags.GrantType == preAuthorizedCodeGrantType {
				return runner.RunOIDC4CIPreAuth(config)
			}

			return runner.RunOIDC4CI(config)
		},
	}

	cmd.Flags().StringVar(&flags.QRCode, "qr-code", "", "path to file with QR code")
	cmd.Flags().StringVar(&flags.InitiateIssuanceURL, "initiate-issuance-url", "", "initiate issuance url")
	cmd.Flags().StringVar(&flags.ClientID, "client-id", "", "oauth2 client ID")
	cmd.Flags().StringVar(&flags.GrantType, "grant-type", "authorization_code", "grant type")
	cmd.Flags().StringSliceVar(&flags.Scope, "scope", nil, "oauth2 scopes. Can be used to pass credential type")
	cmd.Flags().StringVar(&flags.RedirectURI, "redirect-uri", "", "callback where the authorization code should be sent")
	cmd.Flags().StringVar(&flags.VCFormat, "vc-format", "jwt_vc", "vc format [jwt_vc|ldp_vc]")
	cmd.Flags().StringVar(&flags.VCProvider, "vc-provider", "vcs", "vc provider")
	cmd.Flags().StringVar(&flags.LoginURL, "login-url", "", "login url")
	cmd.Flags().StringVar(&flags.CredentialType, "credential-type", "", "credential type")
	cmd.Flags().StringVar(&flags.CredentialFormat, "credential-format", "", "credential format")
	cmd.Flags().BoolVar(&flags.Debug, "debug", false, "enable debug mode")

	return cmd
}
