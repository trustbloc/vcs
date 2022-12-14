/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requestobjectstore

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	txCollection = "request_object_store_tx"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

type mongoDocument struct {
	ID                       primitive.ObjectID     `bson:"_id,omitempty"`
	Content                  string                 `bson:"content"`
	AccessRequestObjectEvent map[string]interface{} `bson:"accessRequestObjectEvent"`
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

// Create creates transaction document in a database.
func (p *Store) Create(
	ctx context.Context,
	request requestobject.RequestObject,
) (*requestobject.RequestObject, error) {
	collection := p.mongoClient.Database().Collection(txCollection)

	event, err := mongodb.StructureToMap(request.AccessRequestObjectEvent)
	if err != nil {
		return nil, fmt.Errorf("create doc: %w", err)
	}

	obj := &mongoDocument{
		ID:                       primitive.ObjectID{},
		Content:                  request.Content,
		AccessRequestObjectEvent: event,
	}

	result, err := collection.InsertOne(ctx, obj)
	if err != nil {
		return nil, err
	}

	insertedID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	request.ID = insertedID.Hex()

	return &request, nil
}

// Find profile by give id.
func (p *Store) Find(
	ctx context.Context,
	id string,
) (*requestobject.RequestObject, error) {
	collection := p.mongoClient.Database().Collection(txCollection)

	txDoc := &mongoDocument{}
	key, keyErr := primitive.ObjectIDFromHex(id)

	if keyErr != nil {
		return nil, keyErr
	}

	err := collection.FindOne(ctx, bson.M{"_id": key}).Decode(txDoc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, requestobject.ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("tx find failed: %w", err)
	}

	event := &spi.Event{}

	err = mongodb.MapToStructure(txDoc.AccessRequestObjectEvent, event)
	if err != nil {
		return nil, fmt.Errorf("access request object event deserialization failed: %w", err)
	}

	return &requestobject.RequestObject{
		ID:                       txDoc.ID.Hex(),
		Content:                  txDoc.Content,
		AccessRequestObjectEvent: event,
	}, nil
}

func (p *Store) Delete(
	ctx context.Context,
	id string,
) error {
	key, keyErr := primitive.ObjectIDFromHex(id)

	if keyErr != nil {
		return keyErr
	}

	collection := p.mongoClient.Database().Collection(txCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_id": key})

	return err
}

// GetResourceURL should return an empty string in current implementation.
// VCS service will build own url.
func (p *Store) GetResourceURL(_ string) string {
	return ""
}
