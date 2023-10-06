/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	timeutil "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
)

const (
	vcStatusStoreName              = "credentialsstatus"
	profileIDMongoDBFieldName      = "profileID"
	profileVersionMongoDBFieldName = "profileVersion"
	credentialIDFieldName          = "vcID"
)

type mongoDocument struct {
	VcID               string              `json:"vcID"`
	ProfileID          string              `json:"profileID"`
	ProfileVersion     string              `json:"profileVersion"`
	TypedID            *verifiable.TypedID `json:"typedID"`
	CredentialMetadata credentialMetadata  `json:"credentialMetadata"`
}

type credentialMetadata struct {
	Issuer         string     `json:"issuer"`
	CredentialType []string   `json:"credentialType"`
	TransactionID  string     `json:"transactionId"`
	IssuanceDate   *time.Time `json:"issuanceDate,omitempty"`
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
}

type getTypedIDEntity struct {
	TypedID *verifiable.TypedID `json:"typedID"`
}

// Store manages verifiable.TypedID in MongoDB.
type Store struct {
	mongoClient *mongodb.Client
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoClient: mongoClient}
}

func (p *Store) Put(
	ctx context.Context,
	profileID string,
	profileVersion string,
	metadata *credentialstatus.CredentialMetadata,
	typedID *verifiable.TypedID) error {
	document := createMongoDocument(profileID, profileVersion, metadata, typedID)

	mongoDBDocument, err := internal.PrepareDataForBSONStorage(document)
	if err != nil {
		return err
	}

	_, err = p.mongoClient.Database().Collection(vcStatusStoreName).InsertOne(ctx, mongoDBDocument)
	if err != nil {
		return fmt.Errorf("insert typedID: %w", err)
	}

	return nil
}

func (p *Store) Get(
	ctx context.Context,
	profileID string,
	profileVersion string,
	credentialID string,
) (*verifiable.TypedID, error) {
	decodeBytes, err := p.mongoClient.Database().Collection(vcStatusStoreName).FindOne(ctx, bson.D{
		{Key: credentialIDFieldName, Value: credentialID},
		{Key: profileIDMongoDBFieldName, Value: profileID},
		{Key: profileVersionMongoDBFieldName, Value: profileVersion},
	}).DecodeBytes()
	if err != nil {
		return nil, fmt.Errorf("find and decode MongoDB: %w", err)
	}

	var entity getTypedIDEntity
	err = json.Unmarshal([]byte(decodeBytes.String()), &entity)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mongoDBDocument: %w", err)
	}

	return entity.TypedID, nil
}

func (p *Store) GetIssuedCredentialsMetadata(
	ctx context.Context,
	profileID string,
	profileVersion string,
) ([]*credentialstatus.CredentialMetadata, error) {
	cursor, err := p.mongoClient.Database().Collection(vcStatusStoreName).Find(ctx, bson.D{
		{Key: profileIDMongoDBFieldName, Value: profileID},
		{Key: profileVersionMongoDBFieldName, Value: profileVersion},
	})
	if err != nil {
		return nil, fmt.Errorf("find credential metadata list MongoDB: %w", err)
	}

	defer func() {
		_ = cursor.Close(ctx)
	}()

	var documentsList []mongoDocument

	if err = cursor.All(ctx, &documentsList); err != nil {
		return nil, fmt.Errorf("decode credential metadata list MongoDB: %w", err)
	}

	return parseMongoDocuments(documentsList), nil
}

func createMongoDocument(
	profileID string,
	profileVersion string,
	metadata *credentialstatus.CredentialMetadata,
	typedID *verifiable.TypedID,
) mongoDocument {
	return mongoDocument{
		VcID:           metadata.CredentialID,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		TypedID:        typedID,
		CredentialMetadata: credentialMetadata{
			Issuer:         metadata.Issuer,
			CredentialType: metadata.CredentialType,
			TransactionID:  metadata.TransactionID,
			IssuanceDate:   getTime(metadata.IssuanceDate),
			ExpirationDate: getTime(metadata.ExpirationDate),
		},
	}
}

func parseMongoDocuments(
	documentsList []mongoDocument,
) []*credentialstatus.CredentialMetadata {
	credentialMetadataList := make([]*credentialstatus.CredentialMetadata, 0, len(documentsList))
	for _, document := range documentsList {
		credentialMetadataList = append(credentialMetadataList, &credentialstatus.CredentialMetadata{
			CredentialID:   document.VcID,
			Issuer:         document.CredentialMetadata.Issuer,
			CredentialType: document.CredentialMetadata.CredentialType,
			TransactionID:  document.CredentialMetadata.TransactionID,
			IssuanceDate:   parseTime(document.CredentialMetadata.IssuanceDate),
			ExpirationDate: parseTime(document.CredentialMetadata.ExpirationDate),
		})
	}

	return credentialMetadataList
}

func getTime(t *timeutil.TimeWrapper) *time.Time {
	if t != nil && !t.IsZero() {
		return &t.Time
	}

	return nil
}

func parseTime(t *time.Time) *timeutil.TimeWrapper {
	if t != nil {
		return timeutil.NewTime(*t)
	}

	return nil
}
