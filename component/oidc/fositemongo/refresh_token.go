package fositemongo

import (
	"context"

	"github.com/ory/fosite"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, refreshTokenCollection, signature, request, defaultTTL)
}

func (s *Store) GetRefreshTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, refreshTokenCollection, signature, session)
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	collection := s.mongoClient.Database().Collection(refreshTokenCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": signature})
	return err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	collection := s.mongoClient.Database().Collection(refreshTokenCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"record.id": requestID})
	return err
}

func (s *Store) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}

	return s.DeleteRefreshTokenSession(ctx, signature)
}
