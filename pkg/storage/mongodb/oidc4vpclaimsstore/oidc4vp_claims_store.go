/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpclaimsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName = "oidc4vp_claims"
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expire_at"`
	*oidc4vp.ClaimData
}

// Store stores claim data with expiration.
type Store struct {
	mongoClient *mongodb.Client
	ttl         int32
}

// New creates presentation claims store.
func New(
	ctx context.Context,
	mongoClient *mongodb.Client,
	ttl int32,
) (*Store, error) {
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

func (s *Store) Create(claims *oidc4vp.ClaimData) (string, error) {
	var err error

	doc := &mongoDocument{
		ExpireAt:  time.Now().Add(time.Duration(s.ttl) * time.Second),
		ClaimData: claims,
	}

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	result, err := s.mongoClient.Database().Collection(collectionName).InsertOne(ctxWithTimeout, doc)
	if err != nil {
		return "", fmt.Errorf("insert received claims data: %w", err)
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *Store) Get(claimDataID string) (*oidc4vp.ClaimData, error) {
	id, err := primitive.ObjectIDFromHex(claimDataID)
	if err != nil {
		return nil, fmt.Errorf("parse id %s: %w", claimDataID, err)
	}

	var doc mongoDocument

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	err = s.mongoClient.Database().Collection(collectionName).FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, oidc4vp.ErrDataNotFound
		}

		return nil, fmt.Errorf("find: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, oidc4vp.ErrDataNotFound
	}

	return doc.ClaimData, nil
}
