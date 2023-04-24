/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthchecks

import (
	"crypto/tls"
	"net/http"

	"github.com/alexliesenfeld/health"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vcs/pkg/observability/health/mongo"
	redischeck "github.com/trustbloc/vcs/pkg/observability/health/redis"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type RedisParameters struct {
	Addrs      []string
	MasterName string
	Password   string
	DisableTLS bool
}

type S3Bucket struct {
	Region string
	Name   string
}

type AWSKMSKey struct {
	Region string
	ID     string
}

type Config struct {
	MongoDBURL      string
	HTTPClient      httpClient
	Cmd             *cobra.Command
	TLSConfig       *tls.Config
	RedisParameters *RedisParameters
	AWSKMSKeys      []AWSKMSKey
	S3Buckets       []S3Bucket
}

func Get(config *Config) []health.Check {
	checks := []health.Check{
		{
			Name:               "mongodb",
			Check:              mongo.New(config.MongoDBURL),
			MaxTimeInError:     1,
			MaxContiguousFails: 1,
		},
	}

	if config.RedisParameters != nil {
		redisOpts := []redischeck.ClientOpt{
			redischeck.WithMasterName(config.RedisParameters.MasterName),
			redischeck.WithPassword(config.RedisParameters.Password),
		}

		if !config.RedisParameters.DisableTLS {
			redisOpts = append(redisOpts, redischeck.WithTLSConfig(config.TLSConfig))
		}

		checks = append(checks, health.Check{
			Name:               "redis",
			Check:              redischeck.New(config.RedisParameters.Addrs, redisOpts...),
			MaxTimeInError:     1,
			MaxContiguousFails: 1,
		})
	}

	return checks
}
