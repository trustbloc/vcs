/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// New returns a new redis health check.
func New(addrs []string, opts ...ClientOpt) func(ctx context.Context) error {
	opt := &clientOpts{}

	for _, f := range opts {
		f(opt)
	}

	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:                 addrs,
		ContextTimeoutEnabled: true,
		MasterName:            opt.masterName,
		Password:              opt.password,
		TLSConfig:             opt.tlsConfig,
	})

	return func(ctx context.Context) error {
		if err := client.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("failed to ping redis: %w", err)
		}

		return nil
	}
}

type clientOpts struct {
	masterName string
	password   string
	tlsConfig  *tls.Config
}

type ClientOpt func(opts *clientOpts)

func WithMasterName(masterName string) ClientOpt {
	return func(opts *clientOpts) {
		opts.masterName = masterName
	}
}

func WithPassword(password string) ClientOpt {
	return func(opts *clientOpts) {
		opts.password = password
	}
}

func WithTLSConfig(tlsConfig *tls.Config) ClientOpt {
	return func(opts *clientOpts) {
		opts.tlsConfig = tlsConfig
	}
}
