/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/cmd/vc-rest/startcmd"
)

var logger = log.New("vc-rest")
var Version string // will be embeded during build

func main() {
	rootCmd := &cobra.Command{
		Use: "vc-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(
		startcmd.WithVersion(Version),
		startcmd.WithServerVersion(os.Getenv("VC_SYSTEM_VERSION")),
	))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("Failed to run vc-rest", log.WithError(err))
	}
}
