/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"crypto/tls"
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
	password      string
	tlsConfig     *tls.Config
	timeout       time.Duration
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

func WithTimeout(timeout time.Duration) ClientOpt {
	return func(opts *clientOpts) {
		opts.timeout = timeout
	}
}

type Client struct {
	client  redis.UniversalClient
	timeout time.Duration
}

// New returns new redis.UniversalClient.
// The type of the returned client depends
// on the following conditions:
//
// 1. If the MasterName option is specified, a sentinel-backed FailoverClient is returned.
// 2. if the number of Addrs is two or more, a ClusterClient is returned.
// 3. Otherwise, a single-node Client is returned.
func New(addrs []string, opts ...ClientOpt) (*Client, error) {
	opt := &clientOpts{
		timeout: defaultTimeout,
	}

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

	if opt.traceProvider != nil {
		err := redisotel.InstrumentTracing(client, redisotel.WithTracerProvider(opt.traceProvider))
		if err != nil {
			return nil, fmt.Errorf("instrument with tracing: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), opt.timeout)
	defer cancel()

	err := client.Ping(ctx).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		client:  client,
		timeout: opt.timeout,
	}, nil
}

func (c *Client) ContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

func (c *Client) API() redis.UniversalClient {
	return c.client
}
