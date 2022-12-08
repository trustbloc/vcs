/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

type oidc4vpCommandFlags struct {
	WalletUserId                  string
	WalletPassPhrase              string
	StorageProvider               string
	StorageProviderConnString     string
	OIDC4VPShouldFetchCredentials bool
	WalletDidKeyID                string
	WalletDidID                   string

	InsecureTls bool
}

// NewOIDC4VPCommand returns a new command for running OIDC4VP flow.
func NewOIDC4VPCommand() *cobra.Command {
	flags := &oidc4vpCommandFlags{}

	cmd := &cobra.Command{
		Use:   "oidc4vp",
		Short: "Run oidc4vp flow",
		Long:  "Run oidc4vp flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			runnerCfg, err := getWalletRunnerConfig(cmd, flags)
			if err != nil {
				return fmt.Errorf("get wallet runner config: %w", err)
			}

			oidc4vpAuthorizationRequest := runnerCfg.oidc4vpAuthorizationRequest
			if oidc4vpAuthorizationRequest == "" {
				var err error
				oidc4vpAuthorizationRequest, err = readQRCode(runnerCfg.qruCodePath)
				if err != nil {
					return fmt.Errorf("unable to recognize QR code: %v", err)
				}
			}

			if oidc4vpAuthorizationRequest == "" {
				return fmt.Errorf("neither oidc4vpAuthorizationRequest nor qrCodePath params supplied")
			}

			runner, err := walletrunner.New(runnerCfg.vcProvider, runnerCfg.options...)
			if err != nil {
				return fmt.Errorf("unable to create wallet runner: %v", err)
			}

			return runner.RunOIDC4VPFlow(oidc4vpAuthorizationRequest)
		},
	}

	createFlags(cmd, flags)

	return cmd
}

func createFlags(cmd *cobra.Command, flags *oidc4vpCommandFlags) {
	cmd.Flags().String("qrcode-path", "", "Path to QR code file")
	cmd.Flags().String("oidc4-vp-authorization-request", "", "OIDC4VP Authorization Request")
	cmd.Flags().String("vc-provider", "vcs", "VC Provider")
	cmd.Flags().String("vc-issuer-url", "", "VC Issuer URL")
	cmd.Flags().String("vc-format", "jwt_vc", "VC format (jwt_vc/ldp_vc)")

	cmd.Flags().String("context-provider-url", "", "context provider. example: https://static-file-server.stg.trustbloc.dev/ld-contexts.json") //nolint
	cmd.Flags().String("did-domain", "", "did domain. example: https://orb-1.stg.trustbloc.dev")                                               //nolint
	cmd.Flags().String("did-service-auth-token", "", "did service authorization token. example: tk1")                                          //nolint
	cmd.Flags().String("uni-resolver-url", "", "uni resolver url. example: https://did-resolver.stg.trustbloc.dev/1.0/identifiers")            //nolint
	cmd.Flags().String("oidc-provider-url", "", "oidc provider url. example: https://orb-1.stg.trustbloc.dev")                                 //nolint
	cmd.Flags().String("oidc-client-id", "", "oidc client id. example: test-org")                                                              //nolint
	cmd.Flags().String("oidc-client-secret", "", "oidc client secret. example: test-org-secret")                                               //nolint
	cmd.Flags().Bool("skip-schema-validation", false, "skip schema validation for while creating vp")                                          //nolint
	cmd.Flags().Bool("oidc4-vp-should-request-credentials", true, "indicates if oidc4vp flow should request new credentials")

	cmd.Flags().BoolVar(&flags.InsecureTls, "insecure", false, "this option allows to skip the verification of ssl\\tls")

	cmd.Flags().StringVar(&flags.WalletUserId, "wallet-user-id", "", "existing wallet user id")
	cmd.Flags().StringVar(&flags.WalletPassPhrase, "wallet-passphrase", "", "existing wallet pass phrase")
	cmd.Flags().StringVar(&flags.StorageProvider, "storage-provider", "", "storage provider. supported: mem,leveldb,mongodb")
	cmd.Flags().StringVar(&flags.StorageProviderConnString, "storage-provider-connection-string", "", "storage provider connection string")

	cmd.Flags().StringVar(&flags.WalletDidID, "wallet-did", "", "existing wallet did")
	cmd.Flags().StringVar(&flags.WalletDidKeyID, "wallet-did-keyid", "", "existing wallet did key id")
}

type runnerConfig struct {
	qruCodePath                 string
	vcProvider                  string
	oidc4vpAuthorizationRequest string
	options                     []vcprovider.ConfigOption
}

func getWalletRunnerConfig(cmd *cobra.Command, flags *oidc4vpCommandFlags) (*runnerConfig, error) {
	qrCodePath, err := cmd.Flags().GetString("qrcode-path")
	if err != nil {
		return nil, fmt.Errorf("qrCodePath flag: %w", err)
	}

	authorizationRequest, err := cmd.Flags().GetString("oidc4-vp-authorization-request")
	if err != nil {
		return nil, fmt.Errorf("oidc4vpAuthorizationRequest flag: %w", err)
	}

	vcProvider, err := cmd.Flags().GetString("vc-provider")
	if err != nil {
		return nil, fmt.Errorf("vcProvider flag: %w", err)
	}

	vcIssuerURL, err := cmd.Flags().GetString("vc-issuer-url")
	if err != nil {
		return nil, fmt.Errorf("vcIssuerURL flag: %w", err)
	}

	vcFormat, err := cmd.Flags().GetString("vc-format")
	if err != nil {
		return nil, fmt.Errorf("vcFormat flag: %w", err)
	}

	runnerOptions := []vcprovider.ConfigOption{
		func(c *vcprovider.Config) {
			c.VCFormat = vcFormat
		},
	}

	if vcIssuerURL != "" {
		runnerOptions = append(runnerOptions, func(c *vcprovider.Config) {
			c.IssueVCURL = vcIssuerURL
		})
	}

	runnerOptions = append(runnerOptions, func(c *vcprovider.Config) {
		if str, _ := cmd.Flags().GetString("context-provider-url"); str != "" {
			c.ContextProviderURL = str
		}
		if str, _ := cmd.Flags().GetString("did-domain"); str != "" {
			c.DidDomain = str
		}
		if str, _ := cmd.Flags().GetString("did-service-auth-token"); str != "" {
			c.DidServiceAuthToken = str
		}
		if str, _ := cmd.Flags().GetString("uni-resolver-url"); str != "" {
			c.UniResolverURL = str
		}

		if str, _ := cmd.Flags().GetString("oidc-provider-url"); str != "" {
			c.OidcProviderURL = str
		}
		if str, _ := cmd.Flags().GetString("oidc-client-id"); str != "" {
			c.OrgName = str
		}
		if str, _ := cmd.Flags().GetString("oidc-client-secret"); str != "" {
			c.OrgSecret = str
		}

		if val, _ := cmd.Flags().GetBool("skip-schema-validation"); val {
			c.SkipSchemaValidation = val
		}

		c.WalletUserId = flags.WalletUserId
		c.WalletPassPhrase = flags.WalletPassPhrase
		c.StorageProvider = flags.StorageProvider
		c.StorageProviderConnString = flags.StorageProviderConnString

		c.WalletDidKeyID = flags.WalletDidKeyID
		c.WalletDidID = flags.WalletDidID

		c.InsecureTls = flags.InsecureTls
		c.OIDC4VPShouldFetchCredentials = flags.OIDC4VPShouldFetchCredentials
	})

	return &runnerConfig{
		qruCodePath:                 qrCodePath,
		oidc4vpAuthorizationRequest: authorizationRequest,
		vcProvider:                  vcProvider,
		options:                     runnerOptions,
	}, nil
}

func readQRCode(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("unable to read image from %s: %w", path, err)
	}
	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("unable to decode image: %w", err)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("unable to create binaty bitmap: %w", err)
	}

	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("unable to decode bitmap: %w", err)
	}

	return result.String(), nil
}
