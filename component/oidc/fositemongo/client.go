package fositemongo

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if id == "" { // for pre-auth we dont have client
		return &fosite.DefaultClient{}, nil
	}

	return getInternal[Client](ctx, s.mongoClient, clientsCollection, id)
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	_, err := getInternal[string](ctx, s.mongoClient, blacklistedJTIsCollection, jti)

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
	collection := s.mongoClient.Database().Collection(blacklistedJTIsCollection)

	obj := &genericDocument[string]{
		ID:       primitive.ObjectID{},
		LookupID: jti,
		Record:   jti,
		ExpireAt: lo.ToPtr(exp),
	}

	_, err := collection.InsertOne(ctx, obj)

	return err
}
