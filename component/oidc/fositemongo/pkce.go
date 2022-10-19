package fositemongo

import (
	"context"

	"github.com/ory/fosite"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, pkceSessionCollection, signature, requester, defaultTTL)
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	collection := s.mongoClient.Database().Collection(pkceSessionCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": signature})
	return err
}

func (s *Store) GetPKCERequestSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, pkceSessionCollection, signature, session)
}
