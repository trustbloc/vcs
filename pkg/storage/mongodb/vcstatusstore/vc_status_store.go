/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"context"
	"encoding/json"
	"fmt"

	mongodbext "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	vcStatusStoreName         = "credentialsstatus"
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

func (p *Store) Put(ctx context.Context, profileID, credentialID string, typedID *verifiable.TypedID) error {
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
	_, err = collection.InsertOne(ctx, mongoDBDocument)
	return err
}

func (p *Store) Get(ctx context.Context, profileID, vcID string) (*verifiable.TypedID, error) {
	collection := p.mongoClient.Database().Collection(vcStatusStoreName)

	decodeBytes, err := collection.FindOne(ctx, bson.D{
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
