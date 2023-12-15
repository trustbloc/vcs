/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
)

type createCommandFlags struct {
	serviceFlags     *serviceFlags
	didMethod        string
	didKeyType       string
	trustRegistryURL string
}

func NewCreateWalletCommand() *cobra.Command {
	flags := &createCommandFlags{
		serviceFlags: &serviceFlags{},
	}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "creates local wallet",
		RunE: func(cmd *cobra.Command, args []string) error {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			svc, err := initServices(flags.serviceFlags, tlsConfig)
			if err != nil {
				return err
			}

			keyCreator, err := svc.CryptoSuite().RawKeyCreator()
			if err != nil {
				return err
			}

			provider := &walletProvider{
				storageProvider: svc.StorageProvider(),
				documentLoader:  svc.DocumentLoader(),
				vdrRegistry:     svc.VDR(),
				keyCreator:      keyCreator,
			}

			slog.Info("creating wallet",
				"did_key_type", flags.didKeyType,
				"did_method", flags.didMethod,
			)

			w, err := wallet.New(
				provider,
				wallet.WithNewDID(flags.didMethod),
				wallet.WithKeyType(kmsapi.KeyType(flags.didKeyType)),
			)
			if err != nil {
				return err
			}

			var dids []any
			for i, did := range w.DIDs() {
				dids = append(dids, fmt.Sprintf("%d", i), did.ID)
			}

			slog.Info("wallet created successfully",
				"signature_type", w.SignatureType(),
				slog.Group("did", dids...),
			)

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.serviceFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.serviceFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")
	cmd.Flags().StringVar(&flags.serviceFlags.contextProviderURL, "context-provider-url", "", "json-ld context provider url")
	cmd.Flags().StringVar(&flags.didMethod, "did-method", "ion", "wallet did methods supported: ion,jwk,key")
	cmd.Flags().StringVar(&flags.didKeyType, "did-key-type", "ED25519", "did key types supported: ED25519,ECDSAP256DER,ECDSAP384DER")

	return cmd
}

type walletProvider struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdrRegistry     vdrapi.Registry
	keyCreator      api.RawKeyCreator
}

func (p *walletProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *walletProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *walletProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *walletProvider) KeyCreator() api.RawKeyCreator {
	return p.keyCreator
}
