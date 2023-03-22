/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	clientsCollection         = "fosite_clients"
	parCollection             = "fosite_par"
	authCodeCollection        = "fosite_auth_code"
	pkceSessionCollection     = "fosite_pkce_sessions"
	refreshTokenCollection    = "fosite_refresh_token_sessions" //nolint: gosec
	accessTokenCollection     = "fosite_access_token_sessions"
	blacklistedJTIsCollection = "fosite_blacklisted_jtis"
	defaultTTL                = 24 * time.Hour
)

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
		clientsCollection: {
			{
				Keys: map[string]interface{}{
					"_lookupId": -1,
				},
				Options: options.Index().SetUnique(true),
			},
		},
		parCollection:             baseSessionIndexes,
		authCodeCollection:        baseSessionIndexes,
		pkceSessionCollection:     baseSessionIndexes,
		refreshTokenCollection:    baseSessionIndexes,
		blacklistedJTIsCollection: baseSessionIndexes,
	}

	for collection, targetIndexes := range indexes {
		if _, err := s.mongoClient.Database().Collection(collection).Indexes().
			CreateMany(ctx, targetIndexes); err != nil {
			return err
		}
	}

	return nil
}
