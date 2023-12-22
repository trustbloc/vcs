/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
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

			var didInfo *wallet.DIDInfo

			if flags.walletDIDIndex != -1 {
				didInfo = w.DIDs()[flags.walletDIDIndex]
			} else {
				didInfo = w.DIDs()[len(w.DIDs())-1]
			}

			signer, err := svc.CryptoSuite().FixedKeyMultiSigner(didInfo.KeyID)
			if err != nil {
				return fmt.Errorf("create signer: %w", err)
			}

			jwsSigner := jwssigner.NewJWSSigner(
				fmt.Sprintf("%s#%s", didInfo.ID, didInfo.KeyID),
				string(w.SignatureType()),
				kmssigner.NewKMSSigner(signer, w.SignatureType(), nil),
			)

			attestationVC, err := attestation.NewClient(
				&attestation.Config{
					HTTPClient:     httpClient,
					DocumentLoader: svc.DocumentLoader(),
					Signer:         jwsSigner,
					WalletDID:      didInfo.ID,
					AttestationURL: flags.attestationURL,
				},
			).GetAttestationVC(context.Background())
			if err != nil {
				return fmt.Errorf("get attestation vc: %w", err)
			}

			vcBytes, err := json.Marshal(attestationVC)
			if err != nil {
				return fmt.Errorf("marshal attestation vc: %w", err)
			}

			if err = w.Add(vcBytes); err != nil {
				return fmt.Errorf("add attestation vc to wallet: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.walletFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.walletFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")
	cmd.Flags().StringVar(&flags.walletFlags.contextProviderURL, "context-provider-url", "", "json-ld context provider url")
	cmd.Flags().StringVar(&flags.attestationURL, "attestation-url", "", "attestation url with profile id and profile version, i.e. <host>/profiles/{profileID}/{profileVersion}/wallet/attestation")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")

	return cmd
}
