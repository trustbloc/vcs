/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/wallet-cli/cmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "wallet-cli",
		Short: "Wallet CLI",
		Long:  "Wallet CLI is a testing tool that emulates Wallet for OIDC4VC flows.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(cmd.NewOIDC4VPCommand())
	rootCmd.AddCommand(cmd.NewOIDC4CICommand())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run wallet-cli: %s", err)
	}
}
