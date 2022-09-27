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
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

type ProfileID = string

// Profile verifier profile.
type Profile struct {
	ID             ProfileID              `json:"id"`
	Name           string                 `json:"name,omitempty"`
	URL            string                 `json:"url,omitempty"`
	Active         bool                   `json:"active"`
	OIDCConfig     interface{}            `json:"oidcConfig"`
	OrganizationID string                 `json:"organizationID"`
	VCConfig       *VCConfig              `json:"vcConfig"`
	KMSConfig      *vcskms.Config         `json:"kmsConfig"`
	SigningDID     *didcreator.SigningDID `json:"signingDID"`
}

// ProfileUpdate contains only unprotected fields from the verifier profile, that can be changed by update api.
type ProfileUpdate struct {
	ID         ProfileID              `json:"id"`
	Name       string                 `json:"name,omitempty"`
	URL        string                 `json:"url,omitempty"`
	OIDCConfig interface{}            `json:"oidcConfig"`
	KMSConfig  *vcskms.Config         `json:"kmsConfig"`
	SigningDID *didcreator.SigningDID `json:"signingDID"`
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Format                  vcsverifiable.Format
	SigningAlgorithm        vcsverifiable.SignatureType
	KeyType                 kms.KeyType
	DIDMethod               didcreator.Method
	SignatureRepresentation verifiable.SignatureRepresentation
	Status                  interface{}
	Context                 []string
}

type profileStore interface {
	Create(profile *Profile, credentialManifests []*cm.CredentialManifest) (ProfileID, error)
	Update(profile *ProfileUpdate) error
	UpdateActiveField(profileID ProfileID, active bool) error
	Delete(profileID ProfileID) error

	Find(strID ProfileID) (*Profile, error)
	FindCredentialManifests(strID ProfileID) ([]*cm.CredentialManifest, error)
	FindByOrgID(orgID string) ([]*Profile, error)
}

type didCreator interface {
	PublicDID(method didcreator.Method, verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
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
	credentialManifests []*cm.CredentialManifest) (*Profile, error) {
	profile.Active = true

	keyCreator, err := p.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed: get keyCreator %w", err)
	}

	createResult, err := p.didCreator.PublicDID(profile.VCConfig.DIDMethod,
		profile.VCConfig.SigningAlgorithm, profile.VCConfig.KeyType, keyCreator)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
	}

	profile.SigningDID = &didcreator.SigningDID{
		DID:            createResult.DocResolution.DIDDocument.ID,
		Creator:        createResult.Creator,
		UpdateKeyURL:   createResult.UpdateKeyURL,
		RecoveryKeyURL: createResult.RecoveryKeyURL,
	}

	id, err := p.store.Create(profile, credentialManifests)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	created, err := p.store.Find(id)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	return created, nil
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
func (p *ProfileService) GetProfile(profileID ProfileID) (*Profile, error) {
	profile, err := p.store.Find(profileID)
	if err != nil {
		return nil, fmt.Errorf("profile service: get profile failed %w", err)
	}

	return profile, nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *ProfileService) GetAllProfiles(orgID string) ([]*Profile, error) {
	profiles, err := p.store.FindByOrgID(orgID)
	if err != nil {
		return nil, fmt.Errorf("profile service: get all profiles failed %w", err)
	}

	return profiles, nil
}
