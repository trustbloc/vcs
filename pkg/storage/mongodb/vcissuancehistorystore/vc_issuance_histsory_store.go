/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcissuancehistorystore

import (
	"context"
	"fmt"
	"time"

	"github.com/samber/lo"
	timeutil "github.com/trustbloc/did-go/doc/util/time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
)

const (
	vcStatusStoreName              = "credential_issuance_history"
	profileIDMongoDBFieldName      = "profileID"
	profileVersionMongoDBFieldName = "profileVersion"
)

type mongoDocument struct {
	ProfileID          string             `json:"profileID"`
	ProfileVersion     string             `json:"profileVersion"`
	CredentialMetadata credentialMetadata `json:"credentialMetadata"`
}

type credentialMetadata struct {
	VcID           string     `json:"vcID"`
	Issuer         string     `json:"issuer"`
	CredentialType []string   `json:"credentialType"`
	TransactionID  string     `json:"transactionId"`
	IssuanceDate   *time.Time `json:"issuanceDate,omitempty"`
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
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
	metadata *credentialstatus.CredentialMetadata) error {
	document := createMongoDocument(profileID, profileVersion, metadata)

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

func (p *Store) GetIssuedCredentialsMetadata(
	ctx context.Context,
	profileID string,
	txID *string,
	credentialID *string,
) ([]*credentialstatus.CredentialMetadata, error) {
	opts := options.Find().SetSort(bson.D{{Key: "credentialMetadata.issuanceDate", Value: -1}})

	query := bson.D{
		{Key: profileIDMongoDBFieldName, Value: profileID},
	}

	if lo.FromPtr(txID) != "" {
		query = append(query, bson.E{Key: "credentialMetadata.transactionId", Value: *txID})
	}
	if lo.FromPtr(credentialID) != "" {
		query = append(query, bson.E{Key: "credentialMetadata.vcID", Value: *credentialID})
	}

	cursor, err := p.mongoClient.Database().Collection(vcStatusStoreName).Find(ctx, query, opts)
	if err != nil {
		return nil, fmt.Errorf("find credential metadata list MongoDB: %w", err)
	}

	defer func() {
		_ = cursor.Close(ctx)
	}()

	var docs []map[string]interface{}
	if err = cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode credential metadata list MongoDB: %w", err)
	}

	return parseMongoDocuments(docs)
}

func createMongoDocument(
	profileID string,
	profileVersion string,
	metadata *credentialstatus.CredentialMetadata,
) mongoDocument {
	return mongoDocument{
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		CredentialMetadata: credentialMetadata{
			VcID:           metadata.CredentialID,
			Issuer:         metadata.Issuer,
			CredentialType: metadata.CredentialType,
			TransactionID:  metadata.TransactionID,
			IssuanceDate:   getTime(metadata.IssuanceDate),
			ExpirationDate: getTime(metadata.ExpirationDate),
		},
	}
}

func parseMongoDocuments(
	docs []map[string]interface{},
) ([]*credentialstatus.CredentialMetadata, error) {
	credentialMetadataList := make([]*credentialstatus.CredentialMetadata, len(docs))
	for i, doc := range docs {
		index := &mongoDocument{}
		if err := mongodb.MapToStructure(doc, index); err != nil {
			return nil, fmt.Errorf("failed to decode to mongoDocument: %w", err)
		}

		credentialMetadataList[i] = &credentialstatus.CredentialMetadata{
			CredentialID:   index.CredentialMetadata.VcID,
			ProfileVersion: index.ProfileVersion,
			Issuer:         index.CredentialMetadata.Issuer,
			CredentialType: index.CredentialMetadata.CredentialType,
			TransactionID:  index.CredentialMetadata.TransactionID,
			IssuanceDate:   parseTime(index.CredentialMetadata.IssuanceDate),
			ExpirationDate: parseTime(index.CredentialMetadata.ExpirationDate),
		}
	}

	return credentialMetadataList, nil
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
