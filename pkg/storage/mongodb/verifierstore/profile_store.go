/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifierstore

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/common"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const profileCollection = "verifier_profile"
const presentationDefinitionCollection = "presentation_definition"

type profileUpdateDocument struct {
	Name       string              `bson:"name,omitempty"`
	URL        string              `bson:"url,omitempty"`
	Checks     *verificationChecks `bson:"checks,omitempty"`
	OIDCConfig interface{}         `bson:"oidcConfig,omitempty"`
}

type profileDocument struct {
	ID             primitive.ObjectID         `bson:"_id,omitempty"`
	Name           string                     `bson:"name"`
	URL            string                     `bson:"url"`
	Active         bool                       `bson:"active"`
	Checks         *verificationChecks        `bson:"checks"`
	OIDCConfig     *oidc4vpConfigDoc          `bson:"oidcConfig"`
	OrganizationID string                     `bson:"organizationId"`
	KMSConfig      *common.KMSConfigDocument  `bson:"kmsConfig"`
	SigningDID     *common.SigningDIDDocument `bson:"signingDID"`
}

type oidc4vpConfigDoc struct {
	SigningAlgorithm vcsverifiable.SignatureType `bson:"signingAlgorithm"`
	DIDMethod        didcreator.Method           `bson:"didMethod"`
	KeyType          kms.KeyType                 `bson:"keyType"`
}

type credentialChecks struct {
	Proof  bool                   `bson:"proof"`
	Format []vcsverifiable.Format `bson:"format"`
	Status bool                   `bson:"status,omitempty"`
}

type presentationChecks struct {
	Proof  bool                   `bson:"proof"`
	Format []vcsverifiable.Format `bson:"format"`
}

type verificationChecks struct {
	Credential   credentialChecks    `bson:"credential"`
	Presentation *presentationChecks `bson:"presentation"`
}

type presentationDefinitionDocument struct {
	ID         primitive.ObjectID     `bson:"_id,omitempty"`
	ProfileID  primitive.ObjectID     `bson:"profileID,omitempty"`
	ExternalID string                 `bson:"externalID,omitempty"`
	Content    map[string]interface{} `bson:"Content,omitempty"`
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
func (p *ProfileStore) Create(profile *verifier.Profile,
	presentationDefinitions []*presexch.PresentationDefinition) (verifier.ProfileID, error) {
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

	profileID := result.InsertedID.(primitive.ObjectID) //nolint:errcheck

	cmCollection := p.mongoClient.Database().Collection(presentationDefinitionCollection)

	var presentationDefinitionDocs []interface{}
	for _, pd := range presentationDefinitions {
		//nolint: govet
		content, err := mongodb.StructureToMap(pd)
		if err != nil {
			return "", fmt.Errorf("issuer profile create: convert credential manifests into map: %w", err)
		}

		presentationDefinitionDocs = append(presentationDefinitionDocs, &presentationDefinitionDocument{
			ProfileID:  profileID,
			Content:    content,
			ExternalID: pd.ID,
		})
	}

	if len(presentationDefinitionDocs) > 0 {
		_, err = cmCollection.InsertMany(ctxWithTimeout, presentationDefinitionDocs)
		if err != nil {
			return "", err
		}
	}

	return profileID.Hex(), nil
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

	profileDoc, err := profileToUpdateDocument(profile)
	if err != nil {
		return err
	}

	//nolint: govet
	result, err := collection.UpdateOne(ctxWithTimeout,
		bson.D{{"_id", id}}, bson.D{{"$set", profileDoc}})
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

	return profileFromDocument(profileDoc)
}

// FindPresentationDefinition give id or return first if id is null.
func (p *ProfileStore) FindPresentationDefinition(strID verifier.ProfileID,
	pdExternalID string) (*presexch.PresentationDefinition, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(presentationDefinitionCollection)

	profileID, err := profileIDFromString(strID)
	if err != nil {
		return nil, err
	}

	pdDoc := &presentationDefinitionDocument{}

	if pdExternalID == "" {
		err = collection.FindOne(ctxWithTimeout, bson.M{"profileID": profileID}).Decode(pdDoc)
	} else {
		err = collection.FindOne(ctxWithTimeout,
			bson.M{
				"profileID":  profileID,
				"externalID": pdExternalID,
			}).Decode(pdDoc)
	}

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, verifier.ErrProfileNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("verifier profile find pd failed: %w", err)
	}

	pd := &presexch.PresentationDefinition{}

	err = mongodb.MapToStructure(pdDoc.Content, pd)
	if err != nil {
		return nil, fmt.Errorf("verifier profile find pd: pd deserialization failed: %w", err)
	}

	return pd, nil
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

		profile, err := profileFromDocument(profileDoc)
		if err != nil {
			return nil, err
		}

		result = append(result, profile)
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

	checks, err := checksToDocument(profile.Checks)
	if err != nil {
		return nil, err
	}

	var oidc4vpConfig *oidc4vpConfigDoc
	if profile.OIDCConfig != nil {
		oidc4vpConfig = &oidc4vpConfigDoc{
			SigningAlgorithm: profile.OIDCConfig.ROSigningAlgorithm,
			DIDMethod:        profile.OIDCConfig.DIDMethod,
			KeyType:          profile.OIDCConfig.KeyType,
		}
	}

	return &profileDocument{
		ID:             id,
		Name:           profile.Name,
		URL:            profile.URL,
		Active:         profile.Active,
		OIDCConfig:     oidc4vpConfig,
		OrganizationID: profile.OrganizationID,
		Checks:         checks,
		KMSConfig:      common.KMSConfigToDocument(profile.KMSConfig),
		SigningDID:     common.SigningDIDToDocument(profile.SigningDID),
	}, nil
}

func profileToUpdateDocument(profile *verifier.ProfileUpdate) (*profileUpdateDocument, error) {
	checks, err := checksToDocument(profile.Checks)
	if err != nil {
		return nil, err
	}

	doc := &profileUpdateDocument{
		Name:   profile.Name,
		URL:    profile.URL,
		Checks: checks,
	}

	return doc, nil
}

func profileFromDocument(doc *profileDocument) (*verifier.Profile, error) {
	var oidc4vpConfig *verifier.OIDC4VPConfig
	if doc.OIDCConfig != nil {
		oidc4vpConfig = &verifier.OIDC4VPConfig{
			ROSigningAlgorithm: doc.OIDCConfig.SigningAlgorithm,
			DIDMethod:          doc.OIDCConfig.DIDMethod,
			KeyType:            doc.OIDCConfig.KeyType,
		}
	}

	profile := &verifier.Profile{
		ID:             doc.ID.Hex(),
		Name:           doc.Name,
		URL:            doc.URL,
		Active:         doc.Active,
		OIDCConfig:     oidc4vpConfig,
		OrganizationID: doc.OrganizationID,
		Checks:         checksFromDocument(doc.Checks),
		KMSConfig:      common.KMSConfigFromDocument(doc.KMSConfig),
		SigningDID:     common.SigningDIDFromDocument(doc.SigningDID),
	}

	return profile, nil
}

func checksToDocument(checks *verifier.VerificationChecks) (*verificationChecks, error) {
	if checks == nil {
		return nil, fmt.Errorf("checks should be not null")
	}

	result := &verificationChecks{
		Credential: credentialChecks{
			Proof:  checks.Credential.Proof,
			Format: checks.Credential.Format,
			Status: checks.Credential.Status,
		},
	}

	if checks.Presentation != nil {
		result.Presentation = &presentationChecks{
			Proof:  checks.Presentation.Proof,
			Format: checks.Presentation.Format,
		}
	}

	return result, nil
}

func checksFromDocument(checks *verificationChecks) *verifier.VerificationChecks {
	result := &verifier.VerificationChecks{
		Credential: verifier.CredentialChecks{
			Proof:  checks.Credential.Proof,
			Format: checks.Credential.Format,
			Status: checks.Credential.Status,
		},
	}

	if checks.Presentation != nil {
		result.Presentation = &verifier.PresentationChecks{
			Proof:  checks.Presentation.Proof,
			Format: checks.Presentation.Format,
		}
	}

	return result
}
