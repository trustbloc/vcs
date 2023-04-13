/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultTimeout = 15 * time.Second
)

type clientOpts struct {
	masterName    string
	traceProvider trace.TracerProvider
}

type ClientOpt func(opts *clientOpts)

func WithTraceProvider(traceProvider trace.TracerProvider) ClientOpt {
	return func(opts *clientOpts) {
		opts.traceProvider = traceProvider
	}
}

func WithMasterName(masterName string) ClientOpt {
	return func(opts *clientOpts) {
		opts.masterName = masterName
	}
}

// New returns new redis.UniversalClient.
// The type of the returned client depends
// on the following conditions:
//
// 1. If the MasterName option is specified, a sentinel-backed FailoverClient is returned.
// 2. if the number of Addrs is two or more, a ClusterClient is returned.
// 3. Otherwise, a single-node Client is returned.
func New(addrs []string, opts ...ClientOpt) (redis.UniversalClient, error) {
	opt := &clientOpts{}
	for _, f := range opts {
		f(opt)
	}

	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:                 addrs,
		ContextTimeoutEnabled: true,
		MasterName:            opt.masterName,
	})

	if opt.traceProvider != nil {
		err := redisotel.InstrumentTracing(client, redisotel.WithTracerProvider(opt.traceProvider))
		if err != nil {
			return nil, fmt.Errorf("instrument with tracing: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	err := client.Ping(ctx).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}
