package fositemongo

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// InsertClient is not required by original interfaces, can be used for testing or data seeding.
func (s *Store) InsertClient(ctx context.Context, client Client) (string, error) {
	collection := s.mongoClient.Database().Collection(clientsCollection)

	obj := &genericDocument[Client]{
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
