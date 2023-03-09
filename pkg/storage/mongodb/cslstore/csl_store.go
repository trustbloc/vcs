/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslstore

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	mongodbext "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	cslStoreName               = "csl_store"
	latestListIDDBEntryKey     = "LatestListID"
	mongoDBDocumentIDFieldName = "_id"
	idFieldName                = "id"

	issuerProfiles   = "/issuer/profiles"
	credentialStatus = "/credentials/status"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

type latestListIDDocument struct {
	ID    string `json:"id,omitempty" bson:"_id,omitempty"`
	Index int    `json:"index,omitempty" bson:"index,omitempty"`
	UUID  string `json:"uuid,omitempty" bson:"uuid,omitempty"`
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

// Upsert does upsert operation of cslWrapper against underlying MongoDB.
func (p *Store) Upsert(cslWrapper *credentialstatus.CSLWrapper) error {
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

// GetCSLURL returns the URL of credentialstatus.CSL.
func (p *Store) GetCSLURL(issuerURL, issuerID string, listIDStr credentialstatus.ListIDStr) (string, error) {
	return url.JoinPath(issuerURL, issuerProfiles, issuerID, credentialStatus, string(listIDStr))
}

// Get returns credentialstatus.CSLWrapper based on credentialstatus.CSL URL.
func (p *Store) Get(cslURL string) (*credentialstatus.CSLWrapper, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctxWithTimeout, bson.M{"_id": cslURL}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, credentialstatus.ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("CSLWrapper find failed: %w", err)
	}

	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if ok {
		vcMap[idFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]
	}

	cslWrapper := &credentialstatus.CSLWrapper{}

	err = mongodb.MapToStructure(mongoDBDocument, cslWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to decode to CSLWrapper: %w", err)
	}

	return cslWrapper, nil
}

func (p *Store) UpdateLatestListID(id int) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)
	_, err := collection.UpdateByID(ctxWithTimeout, latestListIDDBEntryKey, bson.M{
		"$set": latestListIDDocument{
			Index: id,
			UUID:  p.getShortUUID(),
		},
	})

	return err
}

func (p *Store) GetLatestListID() (credentialstatus.ListID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(cslStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctxWithTimeout,
		bson.M{mongoDBDocumentIDFieldName: latestListIDDBEntryKey}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return p.createFirstListID()
	}

	if err != nil {
		return credentialstatus.ListID{}, fmt.Errorf("latestListIDDocument find failed: %w", err)
	}

	latestListID := &latestListIDDocument{}

	err = mongodb.MapToStructure(mongoDBDocument, latestListID)
	if err != nil {
		return credentialstatus.ListID{}, fmt.Errorf("failed to decode to latestListIDDocument: %w", err)
	}

	return credentialstatus.ListID{
		Index: latestListID.Index,
		UUID:  latestListID.UUID,
	}, nil
}

func (p *Store) createFirstListID() (credentialstatus.ListID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	uuidStr := p.getShortUUID()

	collection := p.mongoClient.Database().Collection(cslStoreName)
	_, err := collection.InsertOne(ctxWithTimeout, latestListIDDocument{
		ID:    latestListIDDBEntryKey,
		Index: 1,
		UUID:  uuidStr,
	})
	if err != nil {
		return credentialstatus.ListID{}, fmt.Errorf("failed to create first list id: %w", err)
	}

	return credentialstatus.ListID{
		Index: 1,
		UUID:  uuidStr,
	}, nil
}

func (p *Store) getShortUUID() string {
	return strings.Split(uuid.NewString(), "-")[0]
}
