/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidcnoncestore

import (
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	nonceCollection = "oidcnoncestore"
)

type nonceDocument struct {
	ID     string       `bson:"_id,omitempty"`
	TxID   oidc4vp.TxID `bson:"txID"`
	Expire int64        `bson:"expire"`
}

// TxNonceStore stores oidc transactions in mongo.
type TxNonceStore struct {
	mongoClient *mongodb.Client
}

// New creates TxNonceStore.
func New(mongoClient *mongodb.Client) *TxNonceStore {
	return &TxNonceStore{
		mongoClient: mongoClient,
	}
}

// GetAndDelete get and then delete transaction by one time token.
func (ts *TxNonceStore) GetAndDelete(nonce string) (oidc4vp.TxID, bool, error) {
	ctxWithTimeout, cancel := ts.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := ts.mongoClient.Database().Collection(nonceCollection)

	doc := &nonceDocument{}

	err := collection.FindOneAndDelete(ctxWithTimeout, bson.M{"_id": nonce}).Decode(doc)

	if errors.Is(err, mongo.ErrNoDocuments) || doc.Expire < time.Now().Unix() {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("mongo find failed: %w", err)
	}

	return doc.TxID, true, nil
}

// SetIfNotExist stores transaction if key not exists et.
func (ts *TxNonceStore) SetIfNotExist(nonce string, txID oidc4vp.TxID, expiration time.Duration) (bool, error) {
	ctxWithTimeout, cancel := ts.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := ts.mongoClient.Database().Collection(nonceCollection)

	doc := &nonceDocument{
		ID:     nonce,
		TxID:   txID,
		Expire: time.Now().Add(expiration).Unix(),
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
