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

type profileDocument struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Name       string             `bson:"name,omitempty"`
	URL        string             `bson:"url,omitempty"`
	Checks     interface{}        `bson:"checks,omitempty"`
	OIDCConfig interface{}        `bson:"oidcConfig,omitempty"`
}

type ProfileStore struct {
	mongoClient *mongodb.Client
}

func NewProfileStore(mongoClient *mongodb.Client) *ProfileStore {
	return &ProfileStore{mongoClient: mongoClient}
}

func (p *ProfileStore) Create(profile *verifier.Profile) (string, error) {
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

func (p *ProfileStore) Update(profile *verifier.Profile) error {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	profileDoc, err := profileToDocument(profile)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.UpdateOne(ctxWithTimeout,
		bson.D{{"_id", profileDoc.ID}}, bson.D{{"$set", profileDoc}})
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("profile with given id not found")
	}

	return nil
}

func (p *ProfileStore) Find(strID string) (*verifier.Profile, error) {
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

func profileIDFromString(strID string) (primitive.ObjectID, error) {
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
		ID:         id,
		Name:       profile.Name,
		URL:        profile.URL,
		Checks:     profile.Checks,
		OIDCConfig: profile.OIDCConfig,
	}, nil
}

func profileFromDocument(profile *profileDocument) *verifier.Profile {
	return &verifier.Profile{
		ID:         profile.ID.Hex(),
		Name:       profile.Name,
		URL:        profile.URL,
		Checks:     profile.Checks,
		OIDCConfig: profile.OIDCConfig,
	}
}
