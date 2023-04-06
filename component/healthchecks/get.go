/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthchecks

import (
	"github.com/alexliesenfeld/health"

	"github.com/trustbloc/vcs/component/healthchecks/mongo"
)

type Config struct {
	MongoDBURL string
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
