/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ciclaimdatastore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName = "oidc4vcclaims"
)

type mongoDocument struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt  time.Time          `bson:"expire_at"`
	ClaimData oidc4ci.ClaimData  `bson:"claim_data"`
}

// Store stores claim data with expiration.
type Store struct {
	mongoClient *mongodb.Client
	ttl         int32
}

// New creates a new instance of Store.
func New(ctx context.Context, mongoClient *mongodb.Client, ttl int32) (*Store, error) {
	s := &Store{
		mongoClient: mongoClient,
		ttl:         ttl,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.mongoClient.Database().Collection(collectionName).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: map[string]interface{}{
			"expire_at": 1,
		},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("create index for collection %s: %w", collectionName, err)
	}

	return nil
}

func (s *Store) Create(ctx context.Context, data *oidc4ci.ClaimData) (string, error) {
	doc := &mongoDocument{
		ExpireAt:  time.Now().Add(time.Duration(s.ttl) * time.Second),
		ClaimData: *data,
	}

	result, err := s.mongoClient.Database().Collection(collectionName).InsertOne(ctx, doc)
	if err != nil {
		return "", fmt.Errorf("insert claim data: %w", err)
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *Store) GetAndDelete(ctx context.Context, claimDataID string) (*oidc4ci.ClaimData, error) {
	id, err := primitive.ObjectIDFromHex(claimDataID)
	if err != nil {
		return nil, fmt.Errorf("parse id %s: %w", claimDataID, err)
	}

	var doc mongoDocument

	err = s.mongoClient.Database().Collection(collectionName).FindOneAndDelete(ctx, bson.M{"_id": id}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, resterr.NewCustomError(resterr.DataNotFound, resterr.ErrDataNotFound)
		}

		return nil, fmt.Errorf("find: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, resterr.ErrDataNotFound
	}

	claimData := doc.ClaimData

	return &claimData, nil
}
