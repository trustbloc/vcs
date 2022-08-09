/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"go.mongodb.org/mongo-driver/bson"
	mongodriver "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	vcStoreName                 = "verifiablecredentials"
	profileNameMongoDBFieldName = "profileName"
)

type MongoDBVCStore struct {
	store *mongodb.Store
}

func (m *MongoDBVCSProvider) OpenVCStore() (storage.VCStore, error) {
	ariesStore, err := m.provider.OpenStore(vcStoreName)
	if err != nil {
		return nil, err
	}

	model := mongodriver.IndexModel{
		Keys: bson.D{
			{Key: idFieldName, Value: 1},
			{Key: profileNameMongoDBFieldName, Value: 1},
		},
		Options: mongooptions.Index().SetName("VCIDAndProfileName"),
	}

	err = m.provider.CreateCustomIndexes("VerifiableCredentials", model)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBVCStore{store: mongoDBStore}, nil
}

func (m *MongoDBVCStore) Put(profileName string, vc *verifiable.Credential) error {
	mongoDBDocument, err := mongodb.PrepareDataForBSONStorage(vc)
	if err != nil {
		return err
	}

	mongoDBDocument[profileNameMongoDBFieldName] = profileName

	filter := bson.M{idFieldName: vc.ID, profileNameMongoDBFieldName: profileName}

	writeModel := mongodriver.NewReplaceOneModel().SetFilter(filter).
		SetReplacement(mongoDBDocument).SetUpsert(true)

	return m.store.BulkWrite([]mongodriver.WriteModel{writeModel})
}

func (m *MongoDBVCStore) Get(profileName, vcID string) ([]byte, error) {
	filter := bson.D{
		{Key: idFieldName, Value: vcID},
		{Key: profileNameMongoDBFieldName, Value: profileName},
	}

	iterator, err := m.store.QueryCustom(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query MongoDB: %w", err)
	}

	defer ariesstorage.Close(iterator, nil)

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	if !moreEntries {
		return nil, ariesstorage.ErrDataNotFound
	}

	mongoDBDocument, err := iterator.ValueAsRawMap()
	if err != nil {
		return nil, err
	}

	delete(mongoDBDocument, mongoDBDocumentIDFieldName)
	delete(mongoDBDocument, profileNameMongoDBFieldName)
	// After removing these two fields, we're left with just a VC.

	return json.Marshal(mongoDBDocument)
}
