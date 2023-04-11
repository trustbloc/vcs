/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func New(uri string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
		if err != nil {
			return err
		}

		if err = client.Ping(ctx, readpref.Primary()); err != nil {
			return fmt.Errorf("failed to ping mongodb: %w", err)
		}

		if err = client.Disconnect(ctx); err != nil {
			return err
		}

		return nil
	}
}
