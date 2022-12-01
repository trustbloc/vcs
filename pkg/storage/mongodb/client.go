/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

type Client struct {
	client       *mongo.Client
	databaseName string
	timeout      time.Duration
}

func New(connString string, databaseName string, timeout time.Duration, tlsConfig *tls.Config) (*Client, error) {
	var mongoDBTLS *tls.Config

	if strings.Contains(connString, "tls=true") {
		mongoDBTLS = tlsConfig
	}

	client, err := mongo.NewClient(mongooptions.Client().ApplyURI(connString).SetTLSConfig(mongoDBTLS))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new MongoDB client: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = client.Connect(ctxWithTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	return &Client{
		client:       client,
		databaseName: databaseName,
		timeout:      timeout,
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
