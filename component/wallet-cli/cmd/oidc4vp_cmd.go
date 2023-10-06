/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/spi/crypto"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	storageapi "github.com/trustbloc/kms-go/spi/storage"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vp"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
)

type oidc4vpCommandFlags struct {
	serviceFlags             *serviceFlags
	qrCodePath               string
	walletDIDIndex           int
	linkedDomainVerification bool
}

// NewOIDC4VPCommand returns a new command for running OIDC4VP flow.
func NewOIDC4VPCommand() *cobra.Command {
	flags := &oidc4vpCommandFlags{
		serviceFlags: &serviceFlags{},
	}

	cmd := &cobra.Command{
		Use:   "oidc4vp",
		Short: "presents credential using OIDC4VP flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			svc, initErr := initServices(flags.serviceFlags, tlsConfig)
			if initErr != nil {
				return initErr
			}

			w, err := wallet.New(
				&walletProvider{
					storageProvider: svc.StorageProvider(),
					documentLoader:  svc.DocumentLoader(),
					vdrRegistry:     svc.VDR(),
					kms:             svc.KMS(),
				},
			)
			if err != nil {
				return err
			}

			if len(w.DIDs()) == 0 {
				return fmt.Errorf("wallet is not initialized, please run 'create' command")
			}

			if len(w.DIDs()) < flags.walletDIDIndex {
				return fmt.Errorf("--wallet-did-index is out of range")
			}

			if len(w.DIDs()) > 1 && flags.walletDIDIndex == -1 {
				var dids []any

				for i, did := range w.DIDs() {
					dids = append(dids, fmt.Sprintf("%d", i), did)
				}

				slog.Warn("wallet supports multiple DIDs",
					slog.Group("did", dids...),
				)
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}

			crypt, err := tinkcrypto.New()
			if err != nil {
				return err
			}

			provider := &oidc4vpProvider{
				storageProvider: svc.StorageProvider(),
				httpClient:      httpClient,
				documentLoader:  svc.DocumentLoader(),
				vdrRegistry:     svc.VDR(),
				kms:             svc.KMS(),
				crypt:           crypt,
				wallet:          w,
			}

			authorizationRequest, err := readQRCode(flags.qrCodePath)
			if err != nil {
				return fmt.Errorf("read qr code: %v", err)
			}

			requestURI := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

			var flow *oidc4vp.Flow

			opts := []oidc4vp.Opt{
				oidc4vp.WithRequestURI(requestURI),
			}

			if flags.walletDIDIndex != -1 {
				opts = append(opts, oidc4vp.WithWalletDID(w.DIDs()[flags.walletDIDIndex]))
			} else {
				opts = append(opts, oidc4vp.WithWalletDID(w.DIDs()[len(w.DIDs())-1]))
			}

			if flags.linkedDomainVerification {
				opts = append(opts, oidc4vp.WithLinkedDomainVerification())
			}

			if flow, err = oidc4vp.NewFlow(provider, opts...); err != nil {
				return err
			}

			if err = flow.Run(context.Background()); err != nil {
				return err
			}

			return nil
		},
	}

	createFlags(cmd, flags)

	return cmd
}

func createFlags(cmd *cobra.Command, flags *oidc4vpCommandFlags) {
	cmd.Flags().StringVar(&flags.serviceFlags.storageType, "storage-type", "leveldb", "storage types supported: mem,leveldb,mongodb")
	cmd.Flags().StringVar(&flags.serviceFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")
	cmd.Flags().StringVar(&flags.serviceFlags.levelDBPath, "leveldb-path", "", "leveldb path")

	cmd.Flags().StringVar(&flags.qrCodePath, "qr-code-path", "", "path to file with qr code")
	cmd.Flags().BoolVar(&flags.linkedDomainVerification, "linked-domain-verification", false, "enable linked domain verification")
	cmd.Flags().IntVar(&flags.walletDIDIndex, "wallet-did-index", -1, "index of wallet did, if not set the most recently created DID is used")
}

type oidc4vpProvider struct {
	storageProvider storageapi.Provider
	httpClient      *http.Client
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	kms             kmsapi.KeyManager
	crypt           crypto.Crypto
	wallet          *wallet.Wallet
}

func (p *oidc4vpProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vpProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vpProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vpProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vpProvider) KMS() kmsapi.KeyManager {
	return p.kms
}

func (p *oidc4vpProvider) Crypto() crypto.Crypto {
	return p.crypt
}

func (p *oidc4vpProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
