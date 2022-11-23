/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/trustbloc/vcs/component/walletcli/pkg/service/walletrunner"
	"github.com/trustbloc/vcs/component/walletcli/pkg/service/walletrunner/vcprovider"
)

type runnerConfig struct {
	qruCodePath                 string
	vcProvider                  string
	oidc4vpAuthorizationRequest string
	options                     []vcprovider.ConfigOption
}

func getWalletRunnerConfig() runnerConfig {
	qrCodePath := flag.String("qrCodePath", "", "Path to QR code file")
	oidc4vpAuthorizationRequest := flag.String("oidc4vpAuthorizationRequest", "", "OIDC4VP Authorization Request") // nolint:lll
	vcProvider := flag.String("vcProvider", "vcs", "VC Provider")
	vcIssuerURL := flag.String("vcIssuerURL", "", "VC Issuer URL")
	vcFormat := flag.String("vcFormat", "jwt_vc", "VC format (jwt_vc/ldp_vc)")

	flag.Parse()

	runnerOptions := []vcprovider.ConfigOption{
		func(c *vcprovider.Config) {
			c.VCFormat = *vcFormat
		},
	}

	if *vcIssuerURL != "" {
		runnerOptions = append(runnerOptions, func(c *vcprovider.Config) {
			c.IssueVCURL = *vcIssuerURL
		})
	}

	return runnerConfig{
		qruCodePath:                 *qrCodePath,
		oidc4vpAuthorizationRequest: *oidc4vpAuthorizationRequest,
		vcProvider:                  *vcProvider,
		options:                     runnerOptions,
	}
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

func main() {
	runnerCfg := getWalletRunnerConfig()
	oidc4vpAuthorizationRequest := runnerCfg.oidc4vpAuthorizationRequest
	if oidc4vpAuthorizationRequest == "" {
		var err error
		oidc4vpAuthorizationRequest, err = readQRCode(runnerCfg.qruCodePath)
		if err != nil {
			log.Fatalf("unable to recognize QR code: %v", err)
		}
	}

	if oidc4vpAuthorizationRequest == "" {
		log.Fatalf("neither oidc4vpAuthorizationRequest nor qrCodePath params supplied")
	}

	runner, err := walletrunner.New(runnerCfg.vcProvider, runnerCfg.options...)
	if err != nil {
		log.Fatalf("unable to create wallet runner: %v", err)
	}

	err = runner.RunOIDC4VPFlow(oidc4vpAuthorizationRequest)
	if err != nil {
		log.Fatalf("err: %v", err)
	}
}
