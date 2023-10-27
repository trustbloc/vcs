/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	ClientsSegment         = "fosite_clients"
	BlacklistedJTIsSegment = "fosite_blacklisted_jtis"
)

var _ fosite.ClientManager = (*Store)(nil)

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
	indexes := map[string][]mongo.IndexModel{
		ClientsSegment: {
			{
				Keys: map[string]interface{}{
					"_lookupId": -1,
				},
				Options: options.Index().SetUnique(true),
			},
		},
		BlacklistedJTIsSegment: {
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
		},
	}

	for collection, targetIndexes := range indexes {
		if _, err := s.mongoClient.Database().Collection(collection).Indexes().
			CreateMany(ctx, targetIndexes); err != nil {
			return err
		}
	}

	return nil
}

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if id == "" { // for pre-auth, we don't have client
		return &fosite.DefaultClient{}, nil
	}

	return getInternal[oauth2client.Client](ctx, s.mongoClient, ClientsSegment, id)
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	_, err := getInternal[string](ctx, s.mongoClient, BlacklistedJTIsSegment, jti)

	if errors.Is(err, ErrDataNotFound) {
		return nil
	}

	return fosite.ErrJTIKnown
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	collection := s.mongoClient.Database().Collection(BlacklistedJTIsSegment)

	obj := &genericDocument[string]{
		ID:       primitive.ObjectID{},
		LookupID: jti,
		Record:   jti,
		ExpireAt: lo.ToPtr(exp),
	}

	_, err := collection.InsertOne(ctx, obj)

	return err
}

func (s *Store) InsertClient(ctx context.Context, client *oauth2client.Client) (string, error) {
	collection := s.mongoClient.Database().Collection(ClientsSegment)

	obj := &genericDocument[*oauth2client.Client]{
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

type genericDocument[T any] struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Record   T                  `bson:"record"`
	LookupID string             `bson:"_lookupId"`
	ExpireAt *time.Time         `bson:"expireAt,omitempty"`
}

func getInternal[T any](
	ctx context.Context,
	mongoClient *mongodb.Client,
	dbCollection string,
	lookupID string,
) (*T, error) {
	var doc genericDocument[T]
	collection := mongoClient.Database().Collection(dbCollection)

	err := collection.FindOne(ctx, bson.M{"_lookupId": lookupID}).Decode(&doc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	if doc.ExpireAt != nil && doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, ErrDataNotFound
	}

	return &doc.Record, nil
}
