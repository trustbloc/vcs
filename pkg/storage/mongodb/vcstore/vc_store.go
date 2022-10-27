/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstore

import (
	"encoding/json"
	"fmt"

	mongodbext "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	vcStoreName                 = "verifiablecredentials"
	profileNameMongoDBFieldName = "profileName"
	mongoDBDocumentIDFieldName  = "_id"
	idFieldName                 = "id"
	jwtFieldName                = "jwt"
)

// Store manages profile in mongodb.
type Store struct {
	mongoClient *mongodb.Client
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

func (p *Store) Put(profileName string, vc *verifiable.Credential) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	mongoDBDocument := map[string]interface{}{}
	var err error
	switch {
	case vc.JWT != "":
		mongoDBDocument[idFieldName] = vc.ID
		mongoDBDocument[jwtFieldName] = vc.JWT
	default:
		mongoDBDocument, err = mongodbext.PrepareDataForBSONStorage(vc)
		if err != nil {
			return err
		}
	}
	mongoDBDocument[profileNameMongoDBFieldName] = profileName

	collection := p.mongoClient.Database().Collection(vcStoreName)
	_, err = collection.InsertOne(ctxWithTimeout, mongoDBDocument)
	return err
}

func (p *Store) Get(profileName, vcID string) ([]byte, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(vcStoreName)

	mongoDBDocument := map[string]interface{}{}

	err := collection.FindOne(ctxWithTimeout, bson.D{
		{Key: idFieldName, Value: vcID},
		{Key: profileNameMongoDBFieldName, Value: profileName},
	}).Decode(mongoDBDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to query MongoDB: %w", err)
	}

	if jwt, ok := mongoDBDocument[jwtFieldName].(string); ok {
		return []byte(jwt), nil
	}

	delete(mongoDBDocument, mongoDBDocumentIDFieldName)
	delete(mongoDBDocument, profileNameMongoDBFieldName)

	return json.Marshal(mongoDBDocument)
}
