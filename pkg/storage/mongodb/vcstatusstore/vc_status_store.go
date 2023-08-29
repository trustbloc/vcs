/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	vcStatusStoreName              = "credentialsstatus"
	profileIDMongoDBFieldName      = "profileID"
	profileVersionMongoDBFieldName = "profileVersion"
	credentialIDFieldName          = "vcID"
)

type mongoDocument struct {
	VcID           string              `json:"vcID"`
	ProfileID      string              `json:"profileID"`
	ProfileVersion string              `json:"profileVersion"`
	TypedID        *verifiable.TypedID `json:"typedID"`
}

// Store manages verifiable.TypedID in MongoDB.
type Store struct {
	mongoClient *mongodb.Client
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

func (p *Store) Put(
	ctx context.Context, profileID, profileVersion, credentialID string, typedID *verifiable.TypedID) error {
	document := mongoDocument{
		VcID:           credentialID,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		TypedID:        typedID,
	}

	mongoDBDocument, err := internal.PrepareDataForBSONStorage(document)
	if err != nil {
		return err
	}

	_, err = p.mongoClient.Database().Collection(vcStatusStoreName).InsertOne(ctx, mongoDBDocument)
	if err != nil {
		return fmt.Errorf("insert typedID: %w", err)
	}

	return nil
}

func (p *Store) Get(ctx context.Context, profileID, profileVersion, credentialID string) (*verifiable.TypedID, error) {
	decodeBytes, err := p.mongoClient.Database().Collection(vcStatusStoreName).FindOne(ctx, bson.D{
		{Key: credentialIDFieldName, Value: credentialID},
		{Key: profileIDMongoDBFieldName, Value: profileID},
		{Key: profileVersionMongoDBFieldName, Value: profileVersion},
	}).DecodeBytes()
	if err != nil {
		return nil, fmt.Errorf("find and decode MongoDB: %w", err)
	}

	var mongoDBDocument mongoDocument
	err = json.Unmarshal([]byte(decodeBytes.String()), &mongoDBDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mongoDBDocument: %w", err)
	}

	return mongoDBDocument.TypedID, nil
}
