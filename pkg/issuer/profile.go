/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination profile_mocks_test.go -self_package mocks -package issuer_test -source=profile.go -mock_names profileStore=MockProfileStore,didCreator=MockDIDCreator,kmsRegistry=MockKMSRegistry

package issuer

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

type ProfileID = string

// Profile verifier profile.
type Profile struct {
	ID             ProfileID
	Name           string
	URL            string
	Active         bool
	OIDCConfig     interface{}
	OrganizationID string
	VCConfig       *VCConfig
	KMSConfig      *vcskms.Config
}

// ProfileUpdate contains only unprotected fields from the verifier profile, that can be changed by update api.
type ProfileUpdate struct {
	ID         ProfileID
	Name       string
	URL        string
	OIDCConfig interface{}
	KMSConfig  *vcskms.Config
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Format                  vc.Format
	SigningAlgorithm        vc.SignatureType
	KeyType                 kms.KeyType
	DIDMethod               didcreator.Method
	SignatureRepresentation verifiable.SignatureRepresentation
	Status                  interface{}
	Context                 []string
}

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string
	Creator        string
	UpdateKeyURL   string
	RecoveryKeyURL string
}

type profileStore interface {
	Create(profile *Profile, signingDID *SigningDID, credentialManifests []*cm.CredentialManifest) (ProfileID, error)
	Update(profile *ProfileUpdate) error
	UpdateActiveField(profileID ProfileID, active bool) error
	Delete(profileID ProfileID) error

	Find(strID ProfileID) (*Profile, *SigningDID, error)
	FindCredentialManifests(strID ProfileID) ([]*cm.CredentialManifest, error)
	FindByOrgID(orgID string) ([]*Profile, error)
}

type didCreator interface {
	PublicDID(method didcreator.Method, verificationMethodType vc.SignatureType, keyType kms.KeyType,
		kc didcreator.KeysCreator) (*didcreator.CreateResult, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

// ServiceConfig configure issuer.Service.
type ServiceConfig struct {
	ProfileStore profileStore
	DIDCreator   didCreator
	KMSRegistry  kmsRegistry
}

var ErrProfileNameDuplication = errors.New("profile with same name already exists")
var ErrDataNotFound = errors.New("data not found")

// ProfileService manages verifier profile.
type ProfileService struct {
	store       profileStore
	didCreator  didCreator
	kmsRegistry kmsRegistry
}

// NewProfileService creates ProfileService.
func NewProfileService(config *ServiceConfig) *ProfileService {
	return &ProfileService{
		store:       config.ProfileStore,
		didCreator:  config.DIDCreator,
		kmsRegistry: config.KMSRegistry,
	}
}

// Create creates and returns profile.
func (p *ProfileService) Create(profile *Profile,
	credentialManifests []*cm.CredentialManifest) (*Profile, *SigningDID, error) {
	profile.Active = true

	keyCreator, err := p.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer profile service: create profile failed: get keyCreator %w", err)
	}

	createResult, err := p.didCreator.PublicDID(profile.VCConfig.DIDMethod,
		profile.VCConfig.SigningAlgorithm, profile.VCConfig.KeyType, keyCreator)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
	}

	id, err := p.store.Create(profile, &SigningDID{
		DID:            createResult.DocResolution.DIDDocument.ID,
		Creator:        createResult.Creator,
		UpdateKeyURL:   createResult.UpdateKeyURL,
		RecoveryKeyURL: createResult.RecoveryKeyURL,
	}, credentialManifests)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	created, signingDID, err := p.store.Find(id)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	return created, signingDID, nil
}

// Update updates unprotected files with nonempty fields from ProfileUpdate.
func (p *ProfileService) Update(profile *ProfileUpdate) error {
	err := p.store.Update(profile)
	if err != nil {
		return fmt.Errorf("profile service: update profile failed %w", err)
	}

	return nil
}

// Delete deletes profile with given id.
func (p *ProfileService) Delete(profileID ProfileID) error {
	err := p.store.Delete(profileID)
	if err != nil {
		return fmt.Errorf("profile service: delete profile failed %w", err)
	}

	return nil
}

// ActivateProfile activate profile with given id.
func (p *ProfileService) ActivateProfile(profileID ProfileID) error {
	err := p.store.UpdateActiveField(profileID, true)
	if err != nil {
		return fmt.Errorf("profile service: activate profile failed %w", err)
	}

	return nil
}

// DeactivateProfile deactivate profile with given id.
func (p *ProfileService) DeactivateProfile(profileID ProfileID) error {
	err := p.store.UpdateActiveField(profileID, false)
	if err != nil {
		return fmt.Errorf("profile service: deactivate profile failed %w", err)
	}

	return nil
}

// GetProfile returns profile with given id.
func (p *ProfileService) GetProfile(profileID ProfileID) (*Profile, *SigningDID, error) {
	profile, signingDID, err := p.store.Find(profileID)
	if err != nil {
		return nil, signingDID, fmt.Errorf("issuer profile service: get profile failed: %w", err)
	}

	return profile, signingDID, nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *ProfileService) GetAllProfiles(orgID string) ([]*Profile, error) {
	profiles, err := p.store.FindByOrgID(orgID)
	if err != nil {
		return nil, fmt.Errorf("profile service: get all profiles failed %w", err)
	}

	return profiles, nil
}
