/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslindexstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	cslIndexStoreName          = "csl_store"
	latestListIDDBEntryKey     = "LatestListID"
	mongoDBDocumentIDFieldName = "_id"
	idFieldName                = "id"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

type latestListIDDocument struct {
	ID     string `json:"id,omitempty" bson:"_id,omitempty"`
	ListID string `json:"listId,omitempty" bson:"listId,omitempty"`
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

// Upsert does upsert operation of cslWrapper against underlying MongoDB.
func (p *Store) Upsert(ctx context.Context, cslURL string, cslWrapper *credentialstatus.CSLIndexWrapper) error {
	mongoDBDocument, err := internal.PrepareDataForBSONStorage(cslWrapper)
	if err != nil {
		return err
	}

	collection := p.mongoClient.Database().Collection(cslIndexStoreName)
	_, err = collection.UpdateByID(ctx,
		cslURL, bson.M{
			"$set": mongoDBDocument,
		}, options.Update().SetUpsert(true))
	return err
}

// Get returns credentialstatus.CSLIndexWrapper based on credentialstatus.CSL URL.
func (p *Store) Get(ctx context.Context, cslURL string) (*credentialstatus.CSLIndexWrapper, error) {
	collection := p.mongoClient.Database().Collection(cslIndexStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctx, bson.M{"_id": cslURL}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, credentialstatus.ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("CSLIndexWrapper find failed: %w", err)
	}

	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if ok {
		vcMap[idFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]
	}

	cslWrapper := &credentialstatus.CSLIndexWrapper{}

	err = mongodb.MapToStructure(mongoDBDocument, cslWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to decode to CSLIndexWrapper: %w", err)
	}

	return cslWrapper, nil
}

func (p *Store) UpdateLatestListID(ctx context.Context, id credentialstatus.ListID) error {
	collection := p.mongoClient.Database().Collection(cslIndexStoreName)
	_, err := collection.UpdateByID(ctx, latestListIDDBEntryKey, bson.M{
		"$set": latestListIDDocument{
			ListID: string(id),
		},
	})

	return err
}

func (p *Store) GetLatestListID(ctx context.Context) (credentialstatus.ListID, error) {
	collection := p.mongoClient.Database().Collection(cslIndexStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctx,
		bson.M{mongoDBDocumentIDFieldName: latestListIDDBEntryKey}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return p.createFirstListID(ctx)
	}

	if err != nil {
		return "", fmt.Errorf("latestListIDDocument find failed: %w", err)
	}

	latestListID := &latestListIDDocument{}

	err = mongodb.MapToStructure(mongoDBDocument, latestListID)
	if err != nil {
		return "", fmt.Errorf("failed to decode to latestListIDDocument: %w", err)
	}

	return credentialstatus.ListID(latestListID.ListID), nil
}

func (p *Store) createFirstListID(ctx context.Context) (credentialstatus.ListID, error) {
	listID := uuid.NewString()

	collection := p.mongoClient.Database().Collection(cslIndexStoreName)
	_, err := collection.InsertOne(ctx, latestListIDDocument{
		ID:     latestListIDDBEntryKey,
		ListID: listID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create first list id: %w", err)
	}

	return credentialstatus.ListID(listID), nil
}
