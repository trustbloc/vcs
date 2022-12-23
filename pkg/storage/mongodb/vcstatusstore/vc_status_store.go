/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"encoding/json"
	"fmt"

	mongodbext "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	vcStatusStoreName         = "verifiablecredentialsstatus"
	profileIDMongoDBFieldName = "profileID"
	idFieldName               = "vcID"
)

type mongoDocument struct {
	VcID      string              `json:"vcID"`
	ProfileID string              `json:"profileID"`
	TypedID   *verifiable.TypedID `json:"typedID"`
}

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

func (p *Store) Put(profileID, credentialID string, typedID *verifiable.TypedID) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	document := mongoDocument{
		VcID:      credentialID,
		ProfileID: profileID,
		TypedID:   typedID,
	}

	mongoDBDocument, err := mongodbext.PrepareDataForBSONStorage(document)
	if err != nil {
		return err
	}

	collection := p.mongoClient.Database().Collection(vcStatusStoreName)
	_, err = collection.InsertOne(ctxWithTimeout, mongoDBDocument)
	return err
}

func (p *Store) Get(profileID, vcID string) (*verifiable.TypedID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(vcStatusStoreName)

	decodeBytes, err := collection.FindOne(ctxWithTimeout, bson.D{
		{Key: idFieldName, Value: vcID},
		{Key: profileIDMongoDBFieldName, Value: profileID},
	}).DecodeBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to query MongoDB: %w", err)
	}

	mongoDBDocument := mongoDocument{}
	err = json.Unmarshal([]byte(decodeBytes.String()), &mongoDBDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mongoDBDocument: %w", err)
	}

	return mongoDBDocument.TypedID, nil
}
