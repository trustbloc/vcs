/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpnoncestore

import (
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	nonceCollection = "oidc4vpnoncestore"
)

type nonceDocument struct {
	ID       string       `bson:"_id,omitempty"`
	TxID     oidc4vp.TxID `bson:"txID"`
	ExpireAt time.Time    `bson:"expireAt"`
}

// TxNonceStore stores oidc transactions in mongo.
type TxNonceStore struct {
	mongoClient *mongodb.Client
	ttl         time.Duration
}

// New creates TxNonceStore.
func New(mongoClient *mongodb.Client, ttlSec int32) (*TxNonceStore, error) {
	s := &TxNonceStore{
		mongoClient: mongoClient,
		ttl:         time.Duration(ttlSec) * time.Second,
	}

	if err := s.migrate(); err != nil {
		return nil, err
	}

	return s, nil
}

func (ts *TxNonceStore) migrate() error {
	ctxWithTimeout, cancel := ts.mongoClient.ContextWithTimeout()
	defer cancel()

	if _, err := ts.mongoClient.Database().Collection(nonceCollection).Indexes().
		CreateMany(ctxWithTimeout, []mongo.IndexModel{
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

// GetAndDelete get and then delete transaction by one time token.
func (ts *TxNonceStore) GetAndDelete(nonce string) (oidc4vp.TxID, bool, error) {
	ctxWithTimeout, cancel := ts.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := ts.mongoClient.Database().Collection(nonceCollection)

	doc := &nonceDocument{}

	err := collection.FindOneAndDelete(ctxWithTimeout, bson.M{"_id": nonce}).Decode(doc)

	if errors.Is(err, mongo.ErrNoDocuments) || doc.ExpireAt.Before(time.Now().UTC()) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("mongo find failed: %w", err)
	}

	return doc.TxID, true, nil
}

// SetIfNotExist stores transaction if key not exists et.
func (ts *TxNonceStore) SetIfNotExist(nonce string, txID oidc4vp.TxID) (bool, error) {
	ctxWithTimeout, cancel := ts.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := ts.mongoClient.Database().Collection(nonceCollection)

	doc := &nonceDocument{
		ID:       nonce,
		TxID:     txID,
		ExpireAt: time.Now().Add(ts.ttl),
	}

	_, err := collection.InsertOne(ctxWithTimeout, doc)

	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}
