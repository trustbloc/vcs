/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const defaultTTL = 24 * time.Hour

type Store struct {
	mongoClient *mongodb.Client
}

func NewStore(
	ctx context.Context,
	mongoClient *mongodb.Client,
) (*Store, error) {
	cl := &Store{
		mongoClient: mongoClient,
	}

	if err := cl.migrate(ctx); err != nil {
		return nil, err
	}

	return cl, nil
}

func (s *Store) migrate(ctx context.Context) error {
	baseSessionIndexes := []mongo.IndexModel{
		{
			Keys: map[string]interface{}{
				"_lookupId": -1,
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: map[string]interface{}{
				"expireAt": 1,
			},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}

	indexes := map[string][]mongo.IndexModel{
		dto.ClientsSegment: {
			{
				Keys: map[string]interface{}{
					"_lookupId": -1,
				},
				Options: options.Index().SetUnique(true),
			},
		},
		dto.ParSegment:             baseSessionIndexes,
		dto.AuthCodeSegment:        baseSessionIndexes,
		dto.PkceSessionSegment:     baseSessionIndexes,
		dto.RefreshTokenSegment:    baseSessionIndexes,
		dto.BlacklistedJTIsSegment: baseSessionIndexes,
		dto.AccessTokenSegment:     baseSessionIndexes,
	}

	for collection, targetIndexes := range indexes {
		if _, err := s.mongoClient.Database().Collection(collection).Indexes().
			CreateMany(ctx, targetIndexes); err != nil {
			return err
		}
	}

	return nil
}
