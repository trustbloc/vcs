/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	mongodriver "go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/storage"
)

const (
	cslStoreName           = "credentialstatus"
	latestListIDDBEntryKey = "LatestListID"
)

type MongoDBCSLStore struct {
	store *mongodb.Store
}

func (m *MongoDBVCSProvider) OpenCSLStore() (storage.CSLStore, error) {
	ariesStore, err := m.provider.OpenStore(cslStoreName)
	if err != nil {
		return nil, err
	}

	mongoDBStore, isMongoDBStore := ariesStore.(*mongodb.Store)
	if !isMongoDBStore {
		return nil, errors.New("store from MongoDB provider is of unexpected type")
	}

	return &MongoDBCSLStore{store: mongoDBStore}, nil
}

func (m *MongoDBCSLStore) PutCSLWrapper(cslWrapper *storage.CSLWrapper) error {
	vcID := cslWrapper.VC.ID
	mongoDBDocument, err := mongodb.PrepareDataForBSONStorage(cslWrapper)
	if err != nil {
		return err
	}

	// Save space in the database by using the VC ID name as the MongoDB document _id field
	// and removing the ID from the VC JSON.
	mongoDBDocument[mongoDBDocumentIDFieldName] = vcID

	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if !ok {
		return errors.New("prepared MongoDB document missing VC or couldn't be asserted as a map")
	}

	delete(vcMap, idFieldName)

	filter := bson.M{mongoDBDocumentIDFieldName: cslWrapper.VC.ID}

	writeModel := mongodriver.NewReplaceOneModel().SetFilter(filter).
		SetReplacement(mongoDBDocument).SetUpsert(true)

	return m.store.BulkWrite([]mongodriver.WriteModel{writeModel})
}

func (m *MongoDBCSLStore) GetCSLWrapper(id string) (*storage.CSLWrapper, error) {
	mongoDBDocument, err := m.store.GetAsRawMap(id)
	if err != nil {
		return nil, err
	}

	vcMap, ok := mongoDBDocument["vc"].(map[string]interface{})
	if !ok {
		return nil, errors.New("MongoDB document missing VC or couldn't be asserted as a map")
	}

	vcMap[idFieldName] = mongoDBDocument[mongoDBDocumentIDFieldName]

	cslWrapperBytes, err := json.Marshal(mongoDBDocument)
	if err != nil {
		return nil, err
	}

	var cslWrapper storage.CSLWrapper

	err = json.Unmarshal(cslWrapperBytes, &cslWrapper)
	if err != nil {
		return nil, err
	}

	return &cslWrapper, nil
}

type latestListIDEntry struct {
	ID int `json:"id,omitempty"`
}

func (m *MongoDBCSLStore) UpdateLatestListID(id int) error {
	latestListID := latestListIDEntry{ID: id}

	return m.store.PutAsJSON(latestListIDDBEntryKey, latestListID)
}

func (m *MongoDBCSLStore) GetLatestListID() (int, error) {
	latestListIDAsMap, err := m.store.GetAsRawMap(latestListIDDBEntryKey)
	if err != nil {
		return -1, err
	}

	latestListIDBytes, err := json.Marshal(latestListIDAsMap)
	if err != nil {
		return -1, err
	}

	var latestListID latestListIDEntry

	err = json.Unmarshal(latestListIDBytes, &latestListID)
	if err != nil {
		return -1, err
	}

	return latestListID.ID, nil
}
