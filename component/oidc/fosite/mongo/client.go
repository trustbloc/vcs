/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/oauth2client"
)

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if id == "" { // for pre-auth, we don't have client
		return &fosite.DefaultClient{}, nil
	}

	return getInternal[oauth2client.Client](ctx, s.mongoClient, dto.ClientsSegment, id)
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	_, err := getInternal[string](ctx, s.mongoClient, dto.BlacklistedJTIsSegment, jti)

	if errors.Is(err, dto.ErrDataNotFound) {
		return nil
	}

	return fosite.ErrJTIKnown
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	collection := s.mongoClient.Database().Collection(dto.BlacklistedJTIsSegment)

	obj := &genericDocument[string]{
		ID:       primitive.ObjectID{},
		LookupID: jti,
		Record:   jti,
		ExpireAt: lo.ToPtr(exp),
	}

	_, err := collection.InsertOne(ctx, obj)

	return err
}

func (s *Store) InsertClient(ctx context.Context, client oauth2client.Client) (string, error) {
	collection := s.mongoClient.Database().Collection(dto.ClientsSegment)

	obj := &genericDocument[oauth2client.Client]{
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
