/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"

	"github.com/ory/fosite"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, dto.PkceSessionSegment, signature, requester, defaultTTL)
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	collection := s.mongoClient.Database().Collection(dto.PkceSessionSegment)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": signature})
	return err
}

func (s *Store) GetPKCERequestSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, dto.PkceSessionSegment, signature, session)
}
