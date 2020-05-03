/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package did-rest DID Proxy API.
//
//
// Terms Of Service:
//
//
//     Schemes: http, https
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trustbloc/edge-service/cmd/did-rest/startcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "did-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}))

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run vc-rest: %s", err.Error())
	}
}
