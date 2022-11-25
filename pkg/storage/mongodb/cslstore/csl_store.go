/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslstore

import (
	"encoding/json"
	"errors"
	"fmt"

	mongodbext "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	cslStoreName               = "credentialstatus"
	latestListIDDBEntryKey     = "LatestListID"
	mongoDBDocumentIDFieldName = "_id"
	idFieldName                = "id"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

// CSLWrapper contains CSL and metadata.
type CSLWrapper struct {
	VCByte              json.RawMessage        `json:"vc"`
	Size                int                    `json:"size"`
	RevocationListIndex int                    `json:"revocationListIndex"`
	ListID              int                    `json:"listID"`
	VC                  *verifiable.Credential `json:"-"`
}

type latestListIDDocument struct {
	ID     string `json:"id,omitempty" bson:"_id,omitempty"`
	ListID int    `json:"listId,omitempty" bson:"listId,omitempty"`
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

// Upsert does upsert operation of cslWrapper against underlying MongoDB.
func (p *Store) Upsert(cslWrapper *CSLWrapper) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	mongoDBDocument, err := mongodbext.PrepareDataForBSONStorage(cslWrapper)
	if err != nil {
		return err
	}

	// Save space in the database by using the VC ID name as the MongoDB document _id field
	// and removing the ID from the VC JSON-LD.
	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if ok {
		delete(vcMap, idFieldName)
	}

	collection := p.mongoClient.Database().Collection(cslStoreName)
	_, err = collection.UpdateByID(
		ctxWithTimeout, cslWrapper.VC.ID, bson.M{
			"$set": mongoDBDocument,
		}, options.Update().SetUpsert(true))
	return err
}

// Get returns CSLWrapper.
func (p *Store) Get(id string) (*CSLWrapper, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("CSLWrapper find failed: %w", err)
	}

	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if ok {
		vcMap[idFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]
	}

	cslWrapper := &CSLWrapper{}

	err = mongodb.MapToStructure(mongoDBDocument, cslWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to decode to CSLWrapper: %w", err)
	}

	return cslWrapper, nil
}

func (p *Store) CreateLatestListID(id int) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)
	_, err := collection.InsertOne(ctxWithTimeout, latestListIDDocument{
		ID:     latestListIDDBEntryKey,
		ListID: id,
	})
	return err
}

func (p *Store) UpdateLatestListID(id int) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)
	_, err := collection.UpdateByID(ctxWithTimeout, latestListIDDBEntryKey, bson.M{
		"$set": latestListIDDocument{
			ListID: id,
		},
	})

	return err
}

func (p *Store) GetLatestListID() (int, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctxWithTimeout,
		bson.M{mongoDBDocumentIDFieldName: latestListIDDBEntryKey}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return -1, ErrDataNotFound
	}

	if err != nil {
		return -1, fmt.Errorf("latestListIDDocument find failed: %w", err)
	}

	latestListID := &latestListIDDocument{}

	err = mongodb.MapToStructure(mongoDBDocument, latestListID)
	if err != nil {
		return -1, fmt.Errorf("failed to decode to latestListIDDocument: %w", err)
	}

	return latestListID.ListID, nil
}
