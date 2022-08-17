/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifierstore

import (
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const profileCollection = "verifier_profile"

var ErrDataNotFound = errors.New("data not found")

type profileUpdateDocument struct {
	Name       string      `bson:"name,omitempty"`
	URL        string      `bson:"url,omitempty"`
	Checks     interface{} `bson:"checks,omitempty"`
	OIDCConfig interface{} `bson:"oidcConfig,omitempty"`
}

type profileDocument struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	Name           string             `bson:"name"`
	URL            string             `bson:"url"`
	Active         bool               `bson:"active"`
	Checks         interface{}        `bson:"checks"`
	OIDCConfig     interface{}        `bson:"oidcConfig"`
	OrganizationID string             `bson:"organizationId"`
}

// ProfileStore manages profile in mongodb.
type ProfileStore struct {
	mongoClient *mongodb.Client
}

// NewProfileStore creates ProfileStore.
func NewProfileStore(mongoClient *mongodb.Client) *ProfileStore {
	return &ProfileStore{mongoClient: mongoClient}
}

// Create creates profile document in a database.
func (p *ProfileStore) Create(profile *verifier.Profile) (verifier.ProfileID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	profileDoc, err := profileToDocument(profile)
	if err != nil {
		return "", err
	}

	result, err := collection.InsertOne(ctxWithTimeout, profileDoc)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

// Update updates unprotected fields of profile document in a database.
func (p *ProfileStore) Update(profile *verifier.ProfileUpdate) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	id, err := profileIDFromString(profile.ID)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.UpdateOne(ctxWithTimeout,
		bson.D{{"_id", id}}, bson.D{{"$set", profileUpdateDoc(profile)}})
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("profile with given id not found")
	}

	return nil
}

// UpdateActiveField change 'Active' field of profile document.
func (p *ProfileStore) UpdateActiveField(profileID verifier.ProfileID, active bool) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	id, err := profileIDFromString(profileID)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.UpdateOne(ctxWithTimeout,
		bson.D{{"_id", id}}, bson.D{{"$set", bson.D{{"active", active}}}})
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("profile with given id not found")
	}

	return nil
}

// Delete deletes profile document with give id.
func (p *ProfileStore) Delete(profileID verifier.ProfileID) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	id, err := profileIDFromString(profileID)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.DeleteOne(ctxWithTimeout,
		bson.D{{"_id", id}})
	if err != nil {
		return err
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("profile with given id not found")
	}

	return nil
}

// Find profile by give id.
func (p *ProfileStore) Find(strID verifier.ProfileID) (*verifier.Profile, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	id, err := profileIDFromString(strID)
	if err != nil {
		return nil, err
	}

	profileDoc := &profileDocument{}

	err = collection.FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(profileDoc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrDataNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("verifier profile find failed: %w", err)
	}

	return profileFromDocument(profileDoc), nil
}

// FindByOrgID all profiles by give org id.
func (p *ProfileStore) FindByOrgID(orgID string) ([]*verifier.Profile, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	cur, err := collection.Find(ctxWithTimeout, bson.M{"organizationId": orgID})
	if err != nil {
		return nil, fmt.Errorf("verifier profile find by org id failed: %w", err)
	}

	var result []*verifier.Profile

	for cur.Next(ctxWithTimeout) {
		profileDoc := &profileDocument{}

		err = cur.Decode(profileDoc)
		if err != nil {
			return nil, fmt.Errorf("verifier profile find by org id: decode doc failed: %w", err)
		}

		result = append(result, profileFromDocument(profileDoc))
	}

	return result, nil
}

func profileIDFromString(strID verifier.ProfileID) (primitive.ObjectID, error) {
	if strID == "" {
		return primitive.NilObjectID, nil
	}

	id, err := primitive.ObjectIDFromHex(strID)
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("verifier profile invalid id: %w", err)
	}

	return id, nil
}

func profileToDocument(profile *verifier.Profile) (*profileDocument, error) {
	id, err := profileIDFromString(profile.ID)
	if err != nil {
		return nil, err
	}

	return &profileDocument{
		ID:             id,
		Name:           profile.Name,
		URL:            profile.URL,
		Active:         profile.Active,
		Checks:         profile.Checks,
		OIDCConfig:     profile.OIDCConfig,
		OrganizationID: profile.OrganizationID,
	}, nil
}

func profileUpdateDoc(profile *verifier.ProfileUpdate) *profileUpdateDocument {
	return &profileUpdateDocument{
		Name:       profile.Name,
		URL:        profile.URL,
		Checks:     profile.Checks,
		OIDCConfig: profile.OIDCConfig,
	}
}

func profileFromDocument(profileDoc *profileDocument) *verifier.Profile {
	return &verifier.Profile{
		ID:             profileDoc.ID.Hex(),
		Name:           profileDoc.Name,
		URL:            profileDoc.URL,
		Active:         profileDoc.Active,
		Checks:         profileDoc.Checks,
		OIDCConfig:     profileDoc.OIDCConfig,
		OrganizationID: profileDoc.OrganizationID,
	}
}
