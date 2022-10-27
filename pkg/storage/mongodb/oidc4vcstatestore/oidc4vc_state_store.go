/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vcstatestore

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName    = "oidc4authstate"
	defaultExpiration = 24 * time.Hour
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expireAt"`

	OpState string `bson:"opState,omitempty"`
	State   oidc4vc.OIDC4AuthorizationState
}

// Store stores oidc transactions in mongo.
type Store struct {
	mongoClient *mongodb.Client
}

// New creates TxNonceStore.
func New(ctx context.Context, mongoClient *mongodb.Client) (*Store, error) {
	s := &Store{
		mongoClient: mongoClient,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.mongoClient.Database().Collection(collectionName).Indexes().
		CreateMany(ctx, []mongo.IndexModel{
			{
				Keys: map[string]interface{}{
					"opState": -1,
				},
				Options: options.Index().SetUnique(true),
			},
			{ // ttl index https://www.mongodb.com/community/forums/t/ttl-index-internals/4086/2
				Keys: map[string]interface{}{
					"expireAt": 1,
				},
				Options: options.Index().SetExpireAfterSeconds(0),
			},
		}); err != nil {
		return err
	}

	return nil
}

func (s *Store) StoreAuthorizationState(
	ctx context.Context,
	opState string,
	data oidc4vc.OIDC4AuthorizationState,
	params ...func(insertOptions *oidc4vc.InsertOptions),
) error {
	insertCfg := &oidc4vc.InsertOptions{}
	for _, p := range params {
		p(insertCfg)
	}

	obj := s.mapTransactionDataToMongoDocument(opState, data)

	if insertCfg.TTL != 0 {
		obj.ExpireAt = time.Now().UTC().Add(insertCfg.TTL)
	}

	collection := s.mongoClient.Database().Collection(collectionName)

	_, err := collection.InsertOne(ctx, obj)
	return err
}

func (s *Store) GetAuthorizationState(ctx context.Context, opState string) (*oidc4vc.OIDC4AuthorizationState, error) {
	collection := s.mongoClient.Database().Collection(collectionName)

	var doc mongoDocument

	err := collection.FindOne(ctx, bson.M{
		"opState": opState,
	}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, oidc4vc.ErrDataNotFound
	}
	if err != nil {
		return nil, err
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, oidc4vc.ErrDataNotFound
	}

	return &doc.State, nil
}

func (s *Store) mapTransactionDataToMongoDocument(
	opState string,
	data oidc4vc.OIDC4AuthorizationState,
) *mongoDocument {
	return &mongoDocument{
		ExpireAt: time.Now().UTC().Add(defaultExpiration),
		OpState:  opState,
		State:    data,
	}
}
