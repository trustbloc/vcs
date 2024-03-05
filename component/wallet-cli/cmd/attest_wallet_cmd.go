/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
)

type attestCommandFlags struct {
	walletFlags    *walletFlags
	walletDIDIndex int
	attestationURL string
}

func NewAttestWalletCommand() *cobra.Command {
	flags := &attestCommandFlags{
		walletFlags: &walletFlags{},
	}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "adds attestation vc to wallet",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, svc, err := initWallet(flags.walletFlags)
			if err != nil {
				return fmt.Errorf("init wallet: %w", err)
			}

			if flags.attestationURL == "" {
				return fmt.Errorf("attestation-url is required")
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: svc.TLSConfig(),
				},
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
				flags.walletDIDIndex,
			)
			if err != nil {
				return fmt.Errorf("create attestation service: %w", err)
			}

			if _, err = attestationService.GetAttestation(context.Background()); err != nil {
				return fmt.Errorf("get attestation: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.walletFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.walletFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")
	cmd.Flags().StringVar(&flags.walletFlags.contextProviderURL, "context-provider-url", "", "json-ld context provider url")
	cmd.Flags().StringVar(&flags.attestationURL, "attestation-url", "", "attestation url, i.e. https://<host>/vcs/wallet/attestation")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")

	return cmd
}

type attestationProvider struct {
	storageProvider storageapi.Provider
	httpClient      *http.Client
	documentLoader  ld.DocumentLoader
	cryptoSuite     api.Suite
	wallet          *wallet.Wallet
}

func (p *attestationProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *attestationProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *attestationProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *attestationProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *attestationProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
