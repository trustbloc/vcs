/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifierstore

import (
	"errors"
	"fmt"

	"github.com/jinzhu/copier"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const profileCollection = "verifier_profile"

type profileUpdateDocument struct {
	Name       string              `bson:"name,omitempty"`
	URL        string              `bson:"url,omitempty"`
	Checks     *verificationChecks `bson:"checks,omitempty"`
	OIDCConfig interface{}         `bson:"oidcConfig,omitempty"`
}

type profileDocument struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty"`
	Name           string              `bson:"name"`
	URL            string              `bson:"url"`
	Active         bool                `bson:"active"`
	Checks         *verificationChecks `bson:"checks"`
	OIDCConfig     interface{}         `bson:"oidcConfig"`
	OrganizationID string              `bson:"organizationId"`
}

type credentialChecks struct {
	Proof  bool     `bson:"proof"`
	Format []string `bson:"format"`
	Status bool     `bson:"status,omitempty"`
}

type presentationChecks struct {
	Proof  bool     `bson:"proof"`
	Format []string `bson:"format"`
}

type verificationChecks struct {
	Credential   *credentialChecks   `bson:"credential"`
	Presentation *presentationChecks `bson:"presentation"`
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
		bson.D{{"_id", id}}, bson.D{{"$set", profileToUpdateDocument(profile)}})
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
		return nil, verifier.ErrProfileNotFound
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

	var doc profileDocument

	if err = copier.Copy(&doc, profile); err != nil {
		return nil, err
	}

	doc.ID = id

	return &doc, nil
}

func profileToUpdateDocument(profile *verifier.ProfileUpdate) *profileUpdateDocument {
	doc := &profileUpdateDocument{
		Name:       profile.Name,
		URL:        profile.URL,
		OIDCConfig: profile.OIDCConfig,
	}

	if profile.Checks != nil {
		doc.Checks = &verificationChecks{}

		if profile.Checks.Credential != nil {
			doc.Checks.Credential = &credentialChecks{
				Proof:  profile.Checks.Credential.Proof,
				Status: profile.Checks.Credential.Status,
			}

			for _, format := range profile.Checks.Credential.Format {
				doc.Checks.Credential.Format = append(doc.Checks.Credential.Format, string(format))
			}
		}

		if profile.Checks.Presentation != nil {
			doc.Checks.Presentation = &presentationChecks{
				Proof: profile.Checks.Presentation.Proof,
			}

			for _, format := range profile.Checks.Presentation.Format {
				doc.Checks.Presentation.Format = append(doc.Checks.Presentation.Format, string(format))
			}
		}
	}

	return doc
}

func profileFromDocument(doc *profileDocument) *verifier.Profile {
	profile := &verifier.Profile{
		ID:             doc.ID.Hex(),
		Name:           doc.Name,
		URL:            doc.URL,
		Active:         doc.Active,
		OIDCConfig:     doc.OIDCConfig,
		OrganizationID: doc.OrganizationID,
	}

	if doc.Checks != nil {
		profile.Checks = &verifier.VerificationChecks{}

		if doc.Checks.Credential != nil {
			profile.Checks.Credential = &verifier.CredentialChecks{
				Proof:  doc.Checks.Credential.Proof,
				Status: doc.Checks.Credential.Status,
			}

			for _, format := range doc.Checks.Credential.Format {
				profile.Checks.Credential.Format = append(profile.Checks.Credential.Format,
					vc.Format(format))
			}
		}

		if doc.Checks.Presentation != nil {
			profile.Checks.Presentation = &verifier.PresentationChecks{
				Proof: doc.Checks.Presentation.Proof,
			}

			for _, format := range doc.Checks.Presentation.Format {
				profile.Checks.Presentation.Format = append(profile.Checks.Presentation.Format,
					verifier.PresentationFormat(format))
			}
		}
	}

	return profile
}
