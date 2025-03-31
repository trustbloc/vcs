/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatusstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/internal"
)

var logger = log.New("bv-status-store")

// ErrNotFound is returned when the requested record is not found.
var ErrNotFound = errors.New("not found")

const (
	vcStatusStoreName              = "credentialsstatus"
	profileIDMongoDBFieldName      = "profileID"
	profileVersionMongoDBFieldName = "profileVersion"
	credentialIDFieldName          = "vcID"
)

type mongoDocument struct {
	VcID           string              `json:"vcID"`
	ProfileID      string              `json:"profileID"`
	ProfileVersion string              `json:"profileVersion"`
	TypedID        *verifiable.TypedID `json:"typedID"`
}

type getTypedIDEntity struct {
	TypedID *verifiable.TypedID `json:"typedID"`
}

// Store manages verifiable.TypedID in MongoDB.
type Store struct {
	mongoCollection *mongo.Collection
}

// NewStore creates Store.
func NewStore(mongoClient *mongodb.Client) *Store {
	return &Store{mongoCollection: mongoClient.Database().Collection(vcStatusStoreName)}
}

func (p *Store) Put(
	ctx context.Context,
	profileID string,
	profileVersion string,
	credentialID string,
	typedID *verifiable.TypedID) error {
	document := mongoDocument{
		VcID:           credentialID,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		TypedID:        typedID,
	}

	mongoDBDocument, err := internal.PrepareDataForBSONStorage(document)
	if err != nil {
		return err
	}

	_, err = p.mongoCollection.InsertOne(ctx, mongoDBDocument)
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
	statusPurpose string,
) (*verifiable.TypedID, error) {
	cursor, err := p.mongoCollection.Find(ctx, bson.D{
		{Key: credentialIDFieldName, Value: credentialID},
		{Key: profileIDMongoDBFieldName, Value: profileID},
		{Key: profileVersionMongoDBFieldName, Value: profileVersion},
	})
	if err != nil {
		return nil, fmt.Errorf("mongodb find failed: %w", err)
	}

	defer func() {
		if e := cursor.Close(ctx); e != nil {
			logger.Warnc(ctx, "Error closing MongoDB cursor", log.WithError(e))
		}
	}()

	var docs []*getTypedIDEntity

	if err = cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("cursor get all: %w", err)
	}

	for _, doc := range docs {
		matches, err := matchesStatusPurpose(doc.TypedID, statusPurpose)
		if err != nil {
			return nil, err
		}

		if matches {
			return doc.TypedID, nil
		}
	}

	return nil, fmt.Errorf("no documents in result: %w", ErrNotFound)
}

func matchesStatusPurpose(status *verifiable.TypedID, statusPurpose string) (bool, error) {
	if statusPurpose == "" {
		// Assume it's the default (revocation) status for backward compatibility
		statusPurpose = statustype.DefaultStatusPurpose
	}

	switch vc.StatusType(status.Type) {
	case vc.StatusList2021VCStatus, vc.BitstringStatusList:
		return status.CustomFields[statustype.StatusPurpose] == statusPurpose, nil

	case vc.RevocationList2020VCStatus, vc.RevocationList2021VCStatus:
		return statusPurpose == statustype.StatusPurposeRevocation, nil

	default:
		return false, fmt.Errorf("unsupported status type: %s", status.Type)
	}
}
