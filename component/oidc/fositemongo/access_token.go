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

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, accessTokenCollection, signature, request, defaultTTL)
}

func (s *Store) GetAccessTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, accessTokenCollection, signature, session)
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	collection := s.mongoClient.Database().Collection(accessTokenCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": signature})
	return err
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	collection := s.mongoClient.Database().Collection(accessTokenCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"record.id": requestID})
	return err
}
