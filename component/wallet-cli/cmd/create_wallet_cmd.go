/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
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
	walletFlags *walletFlags
	didMethod   string
	didKeyType  string
	name        string
	version     string
	walletType  string
	compliance  string
}

func NewCreateWalletCommand() *cobra.Command {
	flags := &createCommandFlags{
		walletFlags: &walletFlags{},
	}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "creates local wallet",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := initServices(
				flags.walletFlags.levelDBPath,
				flags.walletFlags.mongoDBConnectionString,
				flags.walletFlags.contextProviderURL,
			)
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

			slog.Debug("creating wallet",
				"did_key_type", flags.didKeyType,
				"did_method", flags.didMethod,
			)

			w, err := wallet.New(
				provider,
				wallet.WithNewDID(flags.didMethod),
				wallet.WithKeyType(kmsapi.KeyType(flags.didKeyType)),
				wallet.WithName(flags.name),
				wallet.WithVersion(flags.version),
				wallet.WithWalletType(flags.walletType),
				wallet.WithCompliance(flags.compliance),
			)
			if err != nil {
				return err
			}

			var dids []any
			for i, did := range w.DIDs() {
				dids = append(dids, fmt.Sprintf("%d", i), did.ID)
			}

			slog.Debug("wallet created successfully",
				"name", w.Name(),
				"version", w.Version(),
				"authentication_method", w.WalletType(),
				"signature_type", w.SignatureType(),
				slog.Group("did", dids...),
			)

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.walletFlags.levelDBPath, "leveldb-path", "", "leveldb path")
	cmd.Flags().StringVar(&flags.walletFlags.mongoDBConnectionString, "mongodb-connection-string", "", "mongodb connection string")
	cmd.Flags().StringVar(&flags.walletFlags.contextProviderURL, "context-provider-url", "", "json-ld context provider url")
	cmd.Flags().StringVar(&flags.didMethod, "did-method", "ion", "wallet did methods supported: ion,jwk,key")
	cmd.Flags().StringVar(&flags.didKeyType, "did-key-type", "ED25519", "did key types supported: ED25519,ECDSAP256DER,ECDSAP384DER")
	cmd.Flags().StringVar(&flags.name, "name", "wallet-cli", "wallet name")
	cmd.Flags().StringVar(&flags.version, "version", "0.1", "wallet version")
	cmd.Flags().StringVar(&flags.walletType, "wallet-type", "some-type", "wallet type")
	cmd.Flags().StringVar(&flags.compliance, "wallet-compliance", "some-compliance", "wallet compliance")

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
