package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/henvic/httpretty"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/formatter"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/refresh"
)

type refreshCommandFlags struct {
	serviceFlags   *walletFlags
	proxyURL       string
	enableTracing  bool
	walletDIDIndex int
}

func NewRefreshCmd() *cobra.Command {
	flags := &refreshCommandFlags{
		serviceFlags: &walletFlags{},
	}

	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh credential",
		Long:  "Refresh credential",
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

			provider := &oidc4vpProvider{
				storageProvider: svc.StorageProvider(),
				httpClient:      httpClient,
				documentLoader:  svc.DocumentLoader(),
				vdrRegistry:     svc.VDR(),
				cryptoSuite:     svc.CryptoSuite(),
				wallet:          w,
			}

			var flow *refresh.Flow

			opts := []refresh.Opt{
				refresh.WithWalletDIDIndex(walletDIDIndex),
			}

			if flow, err = refresh.NewFlow(provider, opts...); err != nil {
				return err
			}

			return flow.Run(context.Background())
		},
	}
}
