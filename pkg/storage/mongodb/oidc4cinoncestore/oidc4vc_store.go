/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cinoncestore

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName = "oidc4vcnoncestore"
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expireAt"`

	OpState                            string `bson:"opState,omitempty"`
	ProfileID                          string
	ProfileVersion                     string
	OrgID                              string
	GrantType                          string
	ResponseType                       string
	Scope                              []string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	RedirectURI                        string
	IssuerAuthCode                     string
	IssuerToken                        string
	IsPreAuthFlow                      bool
	PreAuthCode                        string
	Status                             issuecredential.TransactionState
	WebHookURL                         string
	DID                                string
	UserPin                            string
	WalletInitiatedIssuance            bool
	CredentialConfiguration            []*issuecredential.TxCredentialConfiguration
	RefreshServiceEnabled              bool
}

// Store stores oidc transactions in mongo.
type Store struct {
	defaultTTL  time.Duration
	mongoClient *mongodb.Client
}

// New creates TxNonceStore.
func New(ctx context.Context, mongoClient *mongodb.Client, ttlSec int32) (*Store, error) {
	s := &Store{
		mongoClient: mongoClient,
		defaultTTL:  time.Duration(ttlSec) * time.Second,
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

func (s *Store) ForceCreate(
	ctx context.Context,
	profileTransactionDataTTL int32,
	data *issuecredential.TransactionData,
) (*issuecredential.Transaction, error) {
	return s.createInternal(ctx, profileTransactionDataTTL, data, true)
}

func (s *Store) Create(
	ctx context.Context,
	profileTransactionDataTTL int32,
	data *issuecredential.TransactionData,
) (*issuecredential.Transaction, error) {
	return s.createInternal(ctx, profileTransactionDataTTL, data, false)
}

func (s *Store) createInternal(
	ctx context.Context,
	profileTransactionDataTTL int32,
	data *issuecredential.TransactionData,
	_ bool,
) (*issuecredential.Transaction, error) {
	obj := s.mapTransactionDataToMongoDocument(data)

	if profileTransactionDataTTL != 0 {
		obj.ExpireAt = time.Now().UTC().Add(time.Duration(profileTransactionDataTTL) * time.Second)
	}

	collection := s.mongoClient.Database().Collection(collectionName)

	result, err := collection.InsertOne(ctx, obj)

	if err != nil {
		return nil, err
	}

	insertedID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	return &issuecredential.Transaction{
		ID:              issuecredential.TxID(insertedID.Hex()),
		TransactionData: *data,
	}, nil
}

func (s *Store) Get(
	ctx context.Context,
	txID issuecredential.TxID,
) (*issuecredential.Transaction, error) {
	id, err := primitive.ObjectIDFromHex(string(txID))
	if err != nil {
		return nil, err
	}

	return s.findOne(ctx, bson.M{"_id": id})
}

func (s *Store) FindByOpState(ctx context.Context, opState string) (*issuecredential.Transaction, error) {
	return s.findOne(ctx, bson.M{"opState": opState})
}

func (s *Store) findOne(ctx context.Context, filter interface{}) (*issuecredential.Transaction, error) {
	collection := s.mongoClient.Database().Collection(collectionName)

	var doc mongoDocument

	if err := collection.FindOne(ctx, filter).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, resterr.NewCustomError(resterr.DataNotFound, resterr.ErrDataNotFound)
		}

		return nil, err
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, resterr.NewCustomError(resterr.DataNotFound, resterr.ErrDataNotFound)
	}

	return mapDocumentToTransaction(&doc), nil
}

func (s *Store) Update(ctx context.Context, tx *issuecredential.Transaction) error {
	collection := s.mongoClient.Database().Collection(collectionName)

	id, err := primitive.ObjectIDFromHex(string(tx.ID))
	if err != nil {
		return err
	}

	doc := s.mapTransactionDataToMongoDocument(&tx.TransactionData)

	doc.ID = id
	_, err = collection.UpdateByID(ctx, id, bson.M{
		"$set": doc,
	})

	return err
}

func (s *Store) mapTransactionDataToMongoDocument(data *issuecredential.TransactionData) *mongoDocument {
	return &mongoDocument{
		ID:                                 primitive.ObjectID{},
		ExpireAt:                           time.Now().UTC().Add(s.defaultTTL),
		OpState:                            data.OpState,
		ProfileID:                          data.ProfileID,
		ProfileVersion:                     data.ProfileVersion,
		OrgID:                              data.OrgID,
		GrantType:                          data.GrantType,
		ResponseType:                       data.ResponseType,
		Scope:                              data.Scope,
		AuthorizationEndpoint:              data.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: data.PushedAuthorizationRequestEndpoint,
		TokenEndpoint:                      data.TokenEndpoint,
		RedirectURI:                        data.RedirectURI,
		IssuerAuthCode:                     data.IssuerAuthCode,
		IssuerToken:                        data.IssuerToken,
		UserPin:                            data.UserPin,
		IsPreAuthFlow:                      data.IsPreAuthFlow,
		PreAuthCode:                        data.PreAuthCode,
		Status:                             data.State,
		WebHookURL:                         data.WebHookURL,
		DID:                                data.DID,
		WalletInitiatedIssuance:            data.WalletInitiatedIssuance,
		CredentialConfiguration:            data.CredentialConfiguration,
		RefreshServiceEnabled:              data.RefreshServiceEnabled,
	}
}

func mapDocumentToTransaction(doc *mongoDocument) *issuecredential.Transaction {
	return &issuecredential.Transaction{
		ID: issuecredential.TxID(doc.ID.Hex()),
		TransactionData: issuecredential.TransactionData{
			ProfileID:                          doc.ProfileID,
			ProfileVersion:                     doc.ProfileVersion,
			OrgID:                              doc.OrgID,
			AuthorizationEndpoint:              doc.AuthorizationEndpoint,
			PushedAuthorizationRequestEndpoint: doc.PushedAuthorizationRequestEndpoint,
			TokenEndpoint:                      doc.TokenEndpoint,
			RedirectURI:                        doc.RedirectURI,
			GrantType:                          doc.GrantType,
			ResponseType:                       doc.ResponseType,
			Scope:                              doc.Scope,
			IssuerAuthCode:                     doc.IssuerAuthCode,
			IssuerToken:                        doc.IssuerToken,
			OpState:                            doc.OpState,
			UserPin:                            doc.UserPin,
			IsPreAuthFlow:                      doc.IsPreAuthFlow,
			PreAuthCode:                        doc.PreAuthCode,
			State:                              doc.Status,
			WebHookURL:                         doc.WebHookURL,
			RefreshServiceEnabled:              doc.RefreshServiceEnabled,
			DID:                                doc.DID,
			WalletInitiatedIssuance:            doc.WalletInitiatedIssuance,
			CredentialConfiguration:            doc.CredentialConfiguration,
		},
	}
}
