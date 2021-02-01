/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main Confidential Storage Hub.
//
//
// Terms Of Service:
//
//
//     Schemes: http, https
//     Version: 0.1.0
//     License: Apache-2.0
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
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/cmd/confidential-storage-hub/startcmd"
)

var logger = log.New("confidential-storage-hub")

func main() {
	rootCmd := &cobra.Command{
		Use: "confidential-storage-hub",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("execute root cmd: %s", err.Error())
	}
}
