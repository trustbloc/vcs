/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/cmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "wallet-cli",
		Short: "Wallet CLI",
		Long:  "Wallet CLI is a testing tool that emulates Wallet in OIDC4VCI/OIDC4VP flows.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(cmd.NewCreateWalletCommand())
	rootCmd.AddCommand(cmd.NewAttestWalletCommand())
	rootCmd.AddCommand(cmd.NewOIDC4VCICommand())
	rootCmd.AddCommand(cmd.NewOIDC4VPCommand())

	if err := rootCmd.Execute(); err != nil {
		slog.Error("failed to run wallet-cli", "err", err)
	}
}
