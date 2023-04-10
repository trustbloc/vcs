/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultTimeout = 15 * time.Second
)

type Client struct {
	client       *mongo.Client
	databaseName string
	timeout      time.Duration
}

func New(connString string, databaseName string, opts ...ClientOpt) (*Client, error) {
	op := &clientOpts{
		timeout: defaultTimeout,
	}

	for _, fn := range opts {
		fn(op)
	}

	mongoOpts := mongooptions.Client()
	mongoOpts.ApplyURI(connString)
	mongoOpts.ReadPreference = readpref.SecondaryPreferred()
	mongoOpts.MaxPoolSize = lo.ToPtr(uint64(200))

	if op.traceProvider != nil {
		mongoOpts.Monitor = otelmongo.NewMonitor(otelmongo.WithTracerProvider(op.traceProvider))
	}

	client, err := mongo.NewClient(mongoOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new MongoDB client: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), op.timeout)
	defer cancel()

	err = client.Connect(ctxWithTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	return &Client{
		client:       client,
		databaseName: databaseName,
		timeout:      op.timeout,
	}, nil
}

func (c *Client) Database() *mongo.Database {
	return c.client.Database(c.databaseName)
}

func (c *Client) ContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

func (c *Client) Close() error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	err := c.client.Disconnect(ctxWithTimeout)
	if err != nil {
		if err.Error() == "client is disconnected" {
			return nil
		}

		return fmt.Errorf("failed to disconnect from MongoDB: %w", err)
	}

	return nil
}

type clientOpts struct {
	timeout       time.Duration
	traceProvider trace.TracerProvider
}

type ClientOpt func(opts *clientOpts)

func WithTimeout(timeout time.Duration) ClientOpt {
	return func(opts *clientOpts) {
		opts.timeout = timeout
	}
}

func WithTraceProvider(traceProvider trace.TracerProvider) ClientOpt {
	return func(opts *clientOpts) {
		opts.traceProvider = traceProvider
	}
}
