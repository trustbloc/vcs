/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"context"

	"github.com/ory/fosite"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.createSession(ctx, authCodeCollection, code, request, defaultTTL)
}

func (s *Store) GetAuthorizeCodeSession(
	ctx context.Context,
	code string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, authCodeCollection, code, session)
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	collection := s.mongoClient.Database().Collection(authCodeCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": code})

	return err
}
