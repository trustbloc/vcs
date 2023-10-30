/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_mocks_test.go -package mongo -source=fosite_mongo.go -mock_names mockClientManager=MockClientManager

package mongo

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

var (
	_ fosite.Storage                = (*Store)(nil)
	_ fosite.PARStorage             = (*Store)(nil)
	_ pkce.PKCERequestStorage       = (*Store)(nil)
	_ oauth2.CoreStorage            = (*Store)(nil)
	_ oauth2.TokenRevocationStorage = (*Store)(nil)
)

const defaultTTL = 24 * time.Hour

type mockClientManager interface { //nolint:unused // used to generate mock
	fosite.ClientManager
}

type Store struct {
	mongoClient   *mongodb.Client
	clientManager fosite.ClientManager
}

func NewStore(
	ctx context.Context,
	mongoClient *mongodb.Client,
	clientManager fosite.ClientManager,
) (*Store, error) {
	cl := &Store{
		mongoClient:   mongoClient,
		clientManager: clientManager,
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
		dto.ParSegment:          baseSessionIndexes,
		dto.AuthCodeSegment:     baseSessionIndexes,
		dto.PkceSessionSegment:  baseSessionIndexes,
		dto.RefreshTokenSegment: baseSessionIndexes,
		dto.AccessTokenSegment:  baseSessionIndexes,
	}

	for collection, targetIndexes := range indexes {
		if _, err := s.mongoClient.Database().Collection(collection).Indexes().
			CreateMany(ctx, targetIndexes); err != nil {
			return err
		}
	}

	return nil
}
