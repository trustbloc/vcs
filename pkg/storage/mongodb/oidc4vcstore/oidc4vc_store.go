/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vcstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
	"github.com/trustbloc/vcs/pkg/storage"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName    = "oidcnoncestore"
	defaultExpiration = 24 * time.Hour
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expireAt"`

	OpState              string `bson:"opState,omitempty"`
	CredentialTemplate   []byte
	ClaimEndpoint        string
	GrantType            string
	ResponseType         string
	Scope                []string
	AuthorizationDetails *oidc4vc.AuthorizationDetails
}

// Store stores oidc transactions in mongo.
type Store struct {
	mongoClient *mongodb.Client
}

// New creates TxNonceStore.
func New(ctx context.Context, mongoClient *mongodb.Client) (*Store, error) {
	s := &Store{
		mongoClient: mongoClient,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.mongoClient.Database().Collection(collectionName).Indexes().
		CreateMany(ctx, []mongo.IndexModel{
			{
				Keys: map[string]interface{}{
					"opState": -1,
				},
				Options: options.Index().SetUnique(true),
			},
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

func (s *Store) Create(
	ctx context.Context,
	data *oidc4vc.TransactionData,
	params ...func(insertOptions *storage.InsertOptions),
) (*oidc4vc.Transaction, error) {
	insertCfg := &storage.InsertOptions{}
	for _, p := range params {
		p(insertCfg)
	}

	obj, err := s.mapTransactionDataToMongoDocument(data)

	if err != nil {
		return nil, err
	}

	if insertCfg.TTL > 0 {
		obj.ExpireAt = time.Now().UTC().Add(insertCfg.TTL)
	}

	collection := s.mongoClient.Database().Collection(collectionName)

	result, err := collection.InsertOne(ctx, obj)

	if err != nil && mongo.IsDuplicateKeyError(err) {
		return nil, oidc4vc.ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	insertedID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	return &oidc4vc.Transaction{
		ID:              oidc4vc.TxID(insertedID.Hex()),
		TransactionData: *data,
	}, nil
}

func (s *Store) FindByOpState(ctx context.Context, opState string) (*oidc4vc.Transaction, error) {
	collection := s.mongoClient.Database().Collection(collectionName)

	var doc mongoDocument

	err := collection.FindOne(ctx, bson.M{
		"opState": opState,
	}).Decode(&doc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, oidc4vc.ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, oidc4vc.ErrDataNotFound
	}

	mapped := oidc4vc.TransactionData{
		ClaimEndpoint:        doc.ClaimEndpoint,
		GrantType:            doc.GrantType,
		ResponseType:         doc.ResponseType,
		Scope:                doc.Scope,
		AuthorizationDetails: doc.AuthorizationDetails,
		OpState:              doc.OpState,
	}

	if len(doc.CredentialTemplate) > 0 {
		cred := &verifiable.Credential{}
		if unmarshalErr := json.Unmarshal(doc.CredentialTemplate, cred); unmarshalErr != nil {
			return nil, unmarshalErr
		}

		mapped.CredentialTemplate = cred
	}

	return &oidc4vc.Transaction{
		ID:              oidc4vc.TxID(doc.ID.Hex()),
		TransactionData: mapped,
	}, nil
}

func (s *Store) Update(ctx context.Context, tx *oidc4vc.Transaction) error {
	collection := s.mongoClient.Database().Collection(collectionName)

	id, err := primitive.ObjectIDFromHex(string(tx.ID))
	if err != nil {
		return err
	}

	doc, errMap := s.mapTransactionDataToMongoDocument(&tx.TransactionData)
	if errMap != nil {
		return errMap
	}

	doc.ID = id
	_, err = collection.UpdateByID(ctx, id, bson.M{
		"$set": doc,
	})

	return err
}

func (s *Store) mapTransactionDataToMongoDocument(data *oidc4vc.TransactionData) (*mongoDocument, error) {
	obj := &mongoDocument{
		ExpireAt:             time.Now().UTC().Add(defaultExpiration),
		OpState:              data.OpState,
		ClaimEndpoint:        data.ClaimEndpoint,
		GrantType:            data.GrantType,
		ResponseType:         data.ResponseType,
		Scope:                data.Scope,
		AuthorizationDetails: data.AuthorizationDetails,
	}

	if data.CredentialTemplate != nil {
		cred, marshalErr := data.CredentialTemplate.MarshalJSON()

		if marshalErr != nil {
			return nil, marshalErr
		}

		obj.CredentialTemplate = cred
	}

	return obj, nil
}
