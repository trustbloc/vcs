/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslvcstore

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	cslVCStoreName = "csl_vc_store"

	issuerProfiles   = "/issuer/groups"
	credentialStatus = "/credentials/status"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

// Upsert does upsert operation of cslWrapper against underlying MongoDB.
func (p *Store) Upsert(ctx context.Context, cslURL string, wrapper *credentialstatus.CSLVCWrapper) error {
	mongoDBDocument, err := internal.PrepareDataForBSONStorage(wrapper)
	if err != nil {
		return fmt.Errorf("failed to prepare data for BSON storage: %w", err)
	}

	collection := p.mongoClient.Database().Collection(cslVCStoreName)
	_, err = collection.UpdateByID(ctx,
		cslURL, bson.M{
			"$set": mongoDBDocument,
		}, options.Update().SetUpsert(true))
	return err
}

// GetCSLURL returns the URL of credentialstatus.CSL.
func (p *Store) GetCSLURL(issuerProfileURL, groupID string,
	listID credentialstatus.ListID) (string, error) {
	return url.JoinPath(issuerProfileURL, issuerProfiles, groupID, credentialStatus, string(listID))
}

// Get returns credentialstatus.CSLVCWrapper based on credentialstatus.CSL URL.
func (p *Store) Get(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	collection := p.mongoClient.Database().Collection(cslVCStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctx, bson.M{"_id": cslURL}).Decode(mongoDBDocument)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, credentialstatus.ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("CSL find failed: %w", err)
	}

	wrapper := &credentialstatus.CSLVCWrapper{}

	err = mongodb.MapToStructure(mongoDBDocument, wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to decode to CSLVCWrapper: %w", err)
	}

	return wrapper, nil
}
