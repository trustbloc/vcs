/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

// InsertClient is not required by original interfaces, can be used for testing or data seeding.
func (s *Store) InsertClient(ctx context.Context, client dto.Client) (string, error) {
	collection := s.mongoClient.Database().Collection(dto.ClientsSegment)

	obj := &genericDocument[dto.Client]{
		ID:       primitive.ObjectID{},
		LookupID: client.ID,
		Record:   client,
	}

	result, err := collection.InsertOne(ctx, obj)
	if err != nil {
		return "", err
	}

	insertedID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	return insertedID.Hex(), nil
}
