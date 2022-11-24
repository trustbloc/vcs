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

// NewOIDC4VPCommand returns a new command for running OIDC4VP flow.
func NewOIDC4VPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "oidc4vp",
		Long: "Run oidc4vp flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			runnerCfg, err := getWalletRunnerConfig(cmd)
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

	createFlags(cmd)

	return cmd
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().String("qrCodePath", "", "Path to QR code file")
	cmd.Flags().String("oidc4vpAuthorizationRequest", "", "OIDC4VP Authorization Request")
	cmd.Flags().String("vcProvider", "vcs", "VC Provider")
	cmd.Flags().String("vcIssuerURL", "", "VC Issuer URL")
	cmd.Flags().String("vcFormat", "jwt_vc", "C format (jwt_vc/ldp_vc)")
}

type runnerConfig struct {
	qruCodePath                 string
	vcProvider                  string
	oidc4vpAuthorizationRequest string
	options                     []vcprovider.ConfigOption
}

func getWalletRunnerConfig(cmd *cobra.Command) (*runnerConfig, error) {
	qrCodePath, err := cmd.Flags().GetString("qrCodePath")
	if err != nil {
		return nil, fmt.Errorf("qrCodePath flag: %w", err)
	}

	authorizationRequest, err := cmd.Flags().GetString("oidc4vpAuthorizationRequest")
	if err != nil {
		return nil, fmt.Errorf("oidc4vpAuthorizationRequest flag: %w", err)
	}

	vcProvider, err := cmd.Flags().GetString("vcProvider")
	if err != nil {
		return nil, fmt.Errorf("vcProvider flag: %w", err)
	}

	vcIssuerURL, err := cmd.Flags().GetString("vcIssuerURL")
	if err != nil {
		return nil, fmt.Errorf("vcIssuerURL flag: %w", err)
	}

	vcFormat, err := cmd.Flags().GetString("vcFormat")
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
