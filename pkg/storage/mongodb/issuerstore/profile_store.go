/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuerstore

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/issuer"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	profileCollection = "issuer_profile"
	//nolint: gosec
	credentialManifestCollection = "credential_manifest"
)

type profileUpdateDocument struct {
	Name       string      `bson:"name,omitempty"`
	URL        string      `bson:"url,omitempty"`
	Checks     interface{} `bson:"checks,omitempty"`
	OIDCConfig interface{} `bson:"oidcConfig,omitempty"`
}

type vcConfigDocument struct {
	Format                  vc.Format                          `bson:"format"`
	SigningAlgorithm        vc.SignatureType                   `bson:"signingAlgorithm"`
	KeyType                 arieskms.KeyType                   `bson:"keyType,omitempty"`
	DIDMethod               didcreator.Method                  `bson:"didMethod"`
	SignatureRepresentation verifiable.SignatureRepresentation `bson:"signatureRepresentation"`
	Status                  interface{}                        `bson:"status"`
	Context                 []string                           `bson:"context"`
}

type kmsConfigDocument struct {
	KMSType           kms.Type `bson:"type"`
	Endpoint          string   `bson:"endpoint"`
	SecretLockKeyPath string   `bson:"secretLockKeyPath"`
	DBType            string   `bson:"dbType"`
	DBURL             string   `bson:"dbURL"`
	DBPrefix          string   `bson:"dbPrefix"`
}

type signingDIDDocument struct {
	DID            string `bson:"did"`
	Creator        string `bson:"creator"`
	UpdateKeyURL   string `bson:"updateKeyURL"`
	RecoveryKeyURL string `bson:"recoveryKeyURL"`
}

type profileDocument struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty"`
	Name           string              `bson:"name"`
	URL            string              `bson:"url"`
	Active         bool                `bson:"active"`
	OIDCConfig     interface{}         `bson:"oidcConfig"`
	OrganizationID string              `bson:"organizationId"`
	VCConfig       *vcConfigDocument   `bson:"vcConfig"`
	KMSConfig      *kmsConfigDocument  `bson:"kmsConfig"`
	SigningDID     *signingDIDDocument `bson:"signingDID"`
}

type credentialManifestsDocument struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty"`
	ProfileID primitive.ObjectID     `bson:"profile,omitempty"`
	Content   map[string]interface{} `bson:"Content,omitempty"`
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
func (p *ProfileStore) Create(profile *issuer.Profile, signingDID *issuer.SigningDID,
	credentialManifests []*cm.CredentialManifest) (issuer.ProfileID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	profileDoc, err := profileToDocument(profile, signingDID)
	if err != nil {
		return "", err
	}

	result, err := collection.InsertOne(ctxWithTimeout, profileDoc)
	if err != nil {
		return "", err
	}

	profileID := result.InsertedID.(primitive.ObjectID) //nolint: errcheck

	cmCollection := p.mongoClient.Database().Collection(credentialManifestCollection)

	var credentialManifestsDocs []interface{}
	for _, cm := range credentialManifests {
		//nolint: govet
		content, err := mongodb.StructureToMap(cm)
		if err != nil {
			return "", fmt.Errorf("issuer profile create: convert credential manifests into map: %w", err)
		}

		credentialManifestsDocs = append(credentialManifestsDocs, &credentialManifestsDocument{
			ProfileID: profileID,
			Content:   content,
		})
	}

	if len(credentialManifestsDocs) > 0 {
		_, err = cmCollection.InsertMany(ctxWithTimeout, credentialManifestsDocs)
		if err != nil {
			return "", err
		}
	}

	return profileID.Hex(), nil
}

// Update updates unprotected fields of profile document in a database.
func (p *ProfileStore) Update(profile *issuer.ProfileUpdate) error {
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
func (p *ProfileStore) UpdateActiveField(profileID issuer.ProfileID, active bool) error {
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
func (p *ProfileStore) Delete(profileID issuer.ProfileID) error {
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

	cmCollection := p.mongoClient.Database().Collection(credentialManifestCollection)

	//nolint: govet
	_, err = cmCollection.DeleteMany(ctxWithTimeout,
		bson.D{{"profile", id}})
	if err != nil {
		return err
	}

	return nil
}

// Find profile by give id.
func (p *ProfileStore) Find(strID issuer.ProfileID) (*issuer.Profile, *issuer.SigningDID, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	id, err := profileIDFromString(strID)
	if err != nil {
		return nil, nil, err
	}

	profileDoc := &profileDocument{}

	err = collection.FindOne(ctxWithTimeout, bson.M{"_id": id}).Decode(profileDoc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil, issuer.ErrDataNotFound
	}

	if err != nil {
		return nil, nil, fmt.Errorf("issuer profile find failed: %w", err)
	}

	profile, signingDID := profileFromDocument(profileDoc)

	return profile, signingDID, nil
}

// FindByOrgID all profiles by give org id.
func (p *ProfileStore) FindByOrgID(orgID string) ([]*issuer.Profile, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(profileCollection)

	cur, err := collection.Find(ctxWithTimeout, bson.M{"organizationId": orgID})
	if err != nil {
		return nil, fmt.Errorf("issuer profile find by org id failed: %w", err)
	}

	var result []*issuer.Profile

	for cur.Next(ctxWithTimeout) {
		profileDoc := &profileDocument{}

		err = cur.Decode(profileDoc)
		if err != nil {
			return nil, fmt.Errorf("issuer profile find by org id: decode doc failed: %w", err)
		}

		profile, _ := profileFromDocument(profileDoc)

		result = append(result, profile)
	}

	return result, nil
}

// FindCredentialManifests all CredentialManifests profiles by give profile id.
func (p *ProfileStore) FindCredentialManifests(strID issuer.ProfileID) ([]*cm.CredentialManifest, error) {
	ctxWithTimeout, cancel := p.mongoClient.ContextWithTimeout()
	defer cancel()

	collection := p.mongoClient.Database().Collection(credentialManifestCollection)

	id, err := profileIDFromString(strID)
	if err != nil {
		return nil, err
	}

	cur, err := collection.Find(ctxWithTimeout, bson.M{"profile": id})
	if err != nil {
		return nil, fmt.Errorf("issuer profile find by org id failed: %w", err)
	}

	var result []*cm.CredentialManifest

	for cur.Next(ctxWithTimeout) {
		credentialManifestsDoc := &credentialManifestsDocument{}

		err = cur.Decode(credentialManifestsDoc)
		if err != nil {
			return nil, fmt.Errorf("issuer profile find credential manifests: decode doc failed: %w", err)
		}

		credentialManifest := &cm.CredentialManifest{}

		err = mongodb.MapToStructure(credentialManifestsDoc.Content, credentialManifest)
		if err != nil {
			return nil, fmt.Errorf("issuer profile find credential manifests: decode Content: %w", err)
		}

		result = append(result, credentialManifest)
	}

	return result, nil
}

func profileIDFromString(strID issuer.ProfileID) (primitive.ObjectID, error) {
	if strID == "" {
		return primitive.NilObjectID, nil
	}

	id, err := primitive.ObjectIDFromHex(strID)
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("issuer profile invalid id(%s): %w", strID, err)
	}

	return id, nil
}

func profileToDocument(profile *issuer.Profile, signingDID *issuer.SigningDID) (*profileDocument, error) {
	id, err := profileIDFromString(profile.ID)
	if err != nil {
		return nil, err
	}

	return &profileDocument{
		ID:             id,
		Name:           profile.Name,
		URL:            profile.URL,
		Active:         profile.Active,
		OIDCConfig:     profile.OIDCConfig,
		OrganizationID: profile.OrganizationID,
		VCConfig:       vcConfigToDocument(profile.VCConfig),
		KMSConfig:      kmsConfigToDocument(profile.KMSConfig),
		SigningDID:     signingDIDToDocument(signingDID),
	}, nil
}

func profileUpdateDoc(profile *issuer.ProfileUpdate) *profileUpdateDocument {
	return &profileUpdateDocument{
		Name:       profile.Name,
		URL:        profile.URL,
		OIDCConfig: profile.OIDCConfig,
	}
}

func profileFromDocument(profileDoc *profileDocument) (*issuer.Profile, *issuer.SigningDID) {
	return &issuer.Profile{
		ID:             profileDoc.ID.Hex(),
		Name:           profileDoc.Name,
		URL:            profileDoc.URL,
		Active:         profileDoc.Active,
		OIDCConfig:     profileDoc.OIDCConfig,
		OrganizationID: profileDoc.OrganizationID,
		VCConfig:       vcConfigFromDocument(profileDoc.VCConfig),
		KMSConfig:      kmsConfigFromDocument(profileDoc.KMSConfig),
	}, signingDIDFromDocument(profileDoc.SigningDID)
}

func kmsConfigToDocument(kmsConfig *kms.Config) *kmsConfigDocument {
	if kmsConfig == nil {
		return nil
	}

	return &kmsConfigDocument{
		KMSType:           kmsConfig.KMSType,
		Endpoint:          kmsConfig.Endpoint,
		SecretLockKeyPath: kmsConfig.SecretLockKeyPath,
		DBType:            kmsConfig.DBType,
		DBURL:             kmsConfig.DBURL,
		DBPrefix:          kmsConfig.DBPrefix,
	}
}

func kmsConfigFromDocument(kmsConfig *kmsConfigDocument) *kms.Config {
	if kmsConfig == nil {
		return nil
	}

	return &kms.Config{
		KMSType:           kmsConfig.KMSType,
		Endpoint:          kmsConfig.Endpoint,
		SecretLockKeyPath: kmsConfig.SecretLockKeyPath,
		DBType:            kmsConfig.DBType,
		DBURL:             kmsConfig.DBURL,
		DBPrefix:          kmsConfig.DBPrefix,
	}
}

func vcConfigToDocument(vcConfig *issuer.VCConfig) *vcConfigDocument {
	return &vcConfigDocument{
		Format:                  vcConfig.Format,
		SigningAlgorithm:        vcConfig.SigningAlgorithm,
		KeyType:                 vcConfig.KeyType,
		DIDMethod:               vcConfig.DIDMethod,
		SignatureRepresentation: vcConfig.SignatureRepresentation,
		Status:                  vcConfig.Status,
		Context:                 vcConfig.Context,
	}
}

func vcConfigFromDocument(vcConfig *vcConfigDocument) *issuer.VCConfig {
	return &issuer.VCConfig{
		Format:                  vcConfig.Format,
		SigningAlgorithm:        vcConfig.SigningAlgorithm,
		KeyType:                 vcConfig.KeyType,
		DIDMethod:               vcConfig.DIDMethod,
		SignatureRepresentation: vcConfig.SignatureRepresentation,
		Status:                  vcConfig.Status,
		Context:                 vcConfig.Context,
	}
}

func signingDIDToDocument(signingDID *issuer.SigningDID) *signingDIDDocument {
	return &signingDIDDocument{
		DID:            signingDID.DID,
		Creator:        signingDID.Creator,
		UpdateKeyURL:   signingDID.UpdateKeyURL,
		RecoveryKeyURL: signingDID.RecoveryKeyURL,
	}
}

func signingDIDFromDocument(signingDID *signingDIDDocument) *issuer.SigningDID {
	return &issuer.SigningDID{
		DID:            signingDID.DID,
		Creator:        signingDID.Creator,
		UpdateKeyURL:   signingDID.UpdateKeyURL,
		RecoveryKeyURL: signingDID.RecoveryKeyURL,
	}
}
