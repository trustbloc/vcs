/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistatestore

import (
	"context"
	"errors"
	"strings"
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
	collectionName = "oidc4authstate"
)

var (
	ErrOpStateKeyDuplication = errors.New("op state key duplication")
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expireAt"`

	OpState string `bson:"opState,omitempty"`
	State   *oidc4ci.AuthorizeState
}

// Store stores OIDC4CI authorize request/response state in mongo.
type Store struct {
	defaultTTL  time.Duration
	mongoClient *mongodb.Client
}

// New creates a new instance of Store.
func New(ctx context.Context, mongoClient *mongodb.Client, ttlSec int32) (*Store, error) {
	s := &Store{
		mongoClient: mongoClient,
		defaultTTL:  time.Duration(ttlSec) * time.Second,
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

func (s *Store) SaveAuthorizeState(
	ctx context.Context,
	profileAuthStateTTL int32,
	opState string,
	data *oidc4ci.AuthorizeState,
) error {
	obj := s.mapTransactionDataToMongoDocument(opState, data)
	if profileAuthStateTTL > 0 {
		obj.ExpireAt = time.Now().UTC().Add(time.Duration(profileAuthStateTTL) * time.Second)
	}

	collection := s.mongoClient.Database().Collection(collectionName)

	_, err := collection.InsertOne(ctx, obj)
	if err != nil && strings.Contains(err.Error(), "duplicate key error collection") {
		return ErrOpStateKeyDuplication
	}

	return err
}

func (s *Store) GetAuthorizeState(ctx context.Context, opState string) (*oidc4ci.AuthorizeState, error) {
	collection := s.mongoClient.Database().Collection(collectionName)

	var doc mongoDocument

	err := collection.FindOne(ctx, bson.M{
		"opState": opState,
	}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, resterr.ErrDataNotFound
		}

		return nil, err
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, resterr.ErrDataNotFound
	}

	return doc.State, nil
}

func (s *Store) mapTransactionDataToMongoDocument(
	opState string,
	data *oidc4ci.AuthorizeState,
) *mongoDocument {
	return &mongoDocument{
		ExpireAt: time.Now().UTC().Add(s.defaultTTL),
		OpState:  opState,
		State:    data,
	}
}
