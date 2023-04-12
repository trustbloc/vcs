/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthchecks

import (
	"net/http"

	"github.com/alexliesenfeld/health"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/component/healthchecks/mongo"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	MongoDBURL string
	HTTPClient httpClient
	Cmd        *cobra.Command
}

func Get(config *Config) []health.Check {
	return []health.Check{
		{
			Name:               "mongodb",
			Check:              mongo.New(config.MongoDBURL),
			MaxTimeInError:     1,
			MaxContiguousFails: 1,
		},
	}
}
