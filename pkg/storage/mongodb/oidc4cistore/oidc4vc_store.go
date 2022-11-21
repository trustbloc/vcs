/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistore

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	collectionName    = "oidc4vcnoncestore"
	defaultExpiration = 24 * time.Hour
)

type mongoDocument struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	ExpireAt time.Time          `bson:"expireAt"`

	OpState                            string `bson:"opState,omitempty"`
	ProfileID                          string
	CredentialTemplate                 *profileapi.CredentialTemplate
	CredentialFormat                   vcsverifiable.Format
	ClaimEndpoint                      string
	GrantType                          string
	ResponseType                       string
	Scope                              []string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	AuthorizationDetails               *oidc4ci.AuthorizationDetails
	ClientID                           string
	ClientSecret                       string
	RedirectURI                        string
	IssuerAuthCode                     string
	IssuerToken                        string
	UserPinRequired                    bool
	IsPreAuthFlow                      bool
	PreAuthCode                        string
	ClaimData                          map[string]interface{}
	Status                             oidc4ci.TransactionState
	WebHookURL                         string
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
	data *oidc4ci.TransactionData,
	params ...func(insertOptions *oidc4ci.InsertOptions),
) (*oidc4ci.Transaction, error) {
	insertCfg := &oidc4ci.InsertOptions{}
	for _, p := range params {
		p(insertCfg)
	}

	obj := s.mapTransactionDataToMongoDocument(data)

	if insertCfg.TTL != 0 {
		obj.ExpireAt = time.Now().UTC().Add(insertCfg.TTL)
	}

	collection := s.mongoClient.Database().Collection(collectionName)

	result, err := collection.InsertOne(ctx, obj)

	if err != nil && mongo.IsDuplicateKeyError(err) {
		return nil, oidc4ci.ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	insertedID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	return &oidc4ci.Transaction{
		ID:              oidc4ci.TxID(insertedID.Hex()),
		TransactionData: *data,
	}, nil
}

func (s *Store) Get(
	ctx context.Context,
	txID oidc4ci.TxID,
) (*oidc4ci.Transaction, error) {
	id, err := primitive.ObjectIDFromHex(string(txID))
	if err != nil {
		return nil, err
	}

	return s.findOne(ctx, bson.M{"_id": id})
}

func (s *Store) FindByOpState(ctx context.Context, opState string) (*oidc4ci.Transaction, error) {
	return s.findOne(ctx, bson.M{"opState": opState})
}

func (s *Store) findOne(ctx context.Context, filter interface{}) (*oidc4ci.Transaction, error) {
	collection := s.mongoClient.Database().Collection(collectionName)

	var doc mongoDocument

	if err := collection.FindOne(ctx, filter).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, oidc4ci.ErrDataNotFound
		}

		return nil, err
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, oidc4ci.ErrDataNotFound
	}

	return mapDocumentToTransaction(&doc), nil
}

func (s *Store) Update(ctx context.Context, tx *oidc4ci.Transaction) error {
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

func (s *Store) mapTransactionDataToMongoDocument(data *oidc4ci.TransactionData) *mongoDocument {
	return &mongoDocument{
		ID:                                 primitive.ObjectID{},
		ExpireAt:                           time.Now().UTC().Add(defaultExpiration),
		OpState:                            data.OpState,
		ProfileID:                          data.ProfileID,
		CredentialTemplate:                 data.CredentialTemplate,
		CredentialFormat:                   data.CredentialFormat,
		ClaimEndpoint:                      data.ClaimEndpoint,
		GrantType:                          data.GrantType,
		ResponseType:                       data.ResponseType,
		Scope:                              data.Scope,
		AuthorizationEndpoint:              data.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: data.PushedAuthorizationRequestEndpoint,
		TokenEndpoint:                      data.TokenEndpoint,
		AuthorizationDetails:               data.AuthorizationDetails,
		ClientID:                           data.ClientID,
		ClientSecret:                       data.ClientSecret,
		RedirectURI:                        data.RedirectURI,
		IssuerAuthCode:                     data.IssuerAuthCode,
		IssuerToken:                        data.IssuerToken,
		UserPinRequired:                    data.UserPinRequired,
		IsPreAuthFlow:                      data.IsPreAuthFlow,
		PreAuthCode:                        data.PreAuthCode,
		ClaimData:                          data.ClaimData,
		Status:                             data.State,
		WebHookURL:                         data.WebHookURL,
	}
}

func mapDocumentToTransaction(doc *mongoDocument) *oidc4ci.Transaction {
	return &oidc4ci.Transaction{
		ID: oidc4ci.TxID(doc.ID.Hex()),
		TransactionData: oidc4ci.TransactionData{
			ProfileID:                          doc.ProfileID,
			CredentialTemplate:                 doc.CredentialTemplate,
			CredentialFormat:                   doc.CredentialFormat,
			AuthorizationEndpoint:              doc.AuthorizationEndpoint,
			PushedAuthorizationRequestEndpoint: doc.PushedAuthorizationRequestEndpoint,
			TokenEndpoint:                      doc.TokenEndpoint,
			ClaimEndpoint:                      doc.ClaimEndpoint,
			ClientID:                           doc.ClientID,
			ClientSecret:                       doc.ClientSecret,
			RedirectURI:                        doc.RedirectURI,
			GrantType:                          doc.GrantType,
			ResponseType:                       doc.ResponseType,
			Scope:                              doc.Scope,
			AuthorizationDetails:               doc.AuthorizationDetails,
			IssuerAuthCode:                     doc.IssuerAuthCode,
			IssuerToken:                        doc.IssuerToken,
			OpState:                            doc.OpState,
			UserPinRequired:                    doc.UserPinRequired,
			IsPreAuthFlow:                      doc.IsPreAuthFlow,
			PreAuthCode:                        doc.PreAuthCode,
			ClaimData:                          doc.ClaimData,
			State:                              doc.Status,
			WebHookURL:                         doc.WebHookURL,
		},
	}
}
