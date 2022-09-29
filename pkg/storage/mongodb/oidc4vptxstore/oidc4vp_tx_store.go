/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	txCollection = "oidc4vp_tx"
)

type txDocument struct {
	ID                     primitive.ObjectID     `bson:"_id,omitempty"`
	OrganizationID         string                 `bson:"organizationID"`
	PresentationDefinition map[string]interface{} `bson:"presentationDefinition"`
}

// TxStore manages profile in mongodb.
type TxStore struct {
	mongoClient *mongodb.Client
}

// NewTxStore creates TxStore.
func NewTxStore(mongoClient *mongodb.Client) *TxStore {
	return &TxStore{mongoClient: mongoClient}
}

// Create creates transaction document in a database.
func (p *TxStore) Create(pd *presexch.PresentationDefinition, orgID string) (oidc4vp.TxID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	pdContent, err := mongodb.StructureToMap(pd)
	if err != nil {
		return "", fmt.Errorf("create tx doc: %w", err)
	}

	txDoc := &txDocument{
		OrganizationID:         orgID,
		PresentationDefinition: pdContent,
	}

	result, err := collection.InsertOne(ctxWithTimeout, txDoc)
	if err != nil {
		return "", err
	}

	txID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	return oidc4vp.TxID(txID.Hex()), nil
}

// Find profile by give id.
func (p *TxStore) Find(strID oidc4vp.TxID) (*oidc4vp.Transaction, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(txCollection)

	id, err := txIDFromString(strID)
	if err != nil {
		return nil, err
	}

	txDoc := &txDocument{}

	err = collection.FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(txDoc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, oidc4vp.ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("tx find failed: %w", err)
	}

	return txFromDocument(txDoc)
}

func txIDFromString(strID oidc4vp.TxID) (primitive.ObjectID, error) {
	if strID == "" {
		return primitive.NilObjectID, nil
	}

	id, err := primitive.ObjectIDFromHex(string(strID))
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("tx invalid id(%s): %w", strID, err)
	}

	return id, nil
}

func txFromDocument(txDoc *txDocument) (*oidc4vp.Transaction, error) {
	pd := &presexch.PresentationDefinition{}

	err := mongodb.MapToStructure(txDoc.PresentationDefinition, pd)
	if err != nil {
		return nil, fmt.Errorf("oidc4vp tx manager: pd deserialization failed: %w", err)
	}

	return &oidc4vp.Transaction{
		ID:                     oidc4vp.TxID(txDoc.ID.Hex()),
		OrganizationID:         txDoc.OrganizationID,
		PresentationDefinition: pd,
	}, nil
}
