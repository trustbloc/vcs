/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination profile_mocks_test.go -self_package mocks -package verifier_test -source=profile.go -mock_names profileStore=MockProfileStore,didCreator=MockDIDCreator,kmsRegistry=MockKMSRegistry

package verifier

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

var ErrProfileNotFound = errors.New("profile not found")

type ProfileID = string

// Profile is a verifier profile.
type Profile struct {
	ID             ProfileID
	Name           string
	URL            string
	Active         bool
	OrganizationID string
	Checks         *VerificationChecks
	OIDCConfig     *OIDC4VPConfig
	KMSConfig      *vcskms.Config
	SigningDID     *didcreator.SigningDID
}

// OIDC4VPConfig store config for verifier did that used to sign request object in oidc4vp process.
type OIDC4VPConfig struct {
	ROSigningAlgorithm vc.SignatureType
	DIDMethod          didcreator.Method
	KeyType            kms.KeyType
}

// ProfileUpdate contains only unprotected fields from the verifier profile, that can be changed by update API.
type ProfileUpdate struct {
	ID     ProfileID
	Name   string
	URL    string
	Checks *VerificationChecks
}

// CredentialChecks are checks to be performed during credential verification.
type CredentialChecks struct {
	Proof  bool
	Format []vc.Format
	Status bool
}

// PresentationChecks are checks to be performed during presentation verification.
type PresentationChecks struct {
	Proof  bool
	Format []vc.Format
}

// VerificationChecks are checks to be performed for verifying credentials and presentations.
type VerificationChecks struct {
	Credential   CredentialChecks
	Presentation *PresentationChecks
}

type profileStore interface {
	Create(profile *Profile, presentationDefinitions []*presexch.PresentationDefinition) (ProfileID, error)
	Update(profile *ProfileUpdate) error
	UpdateActiveField(profileID ProfileID, active bool) error
	Delete(profileID ProfileID) error

	Find(strID ProfileID) (*Profile, error)
	FindByOrgID(orgID string) ([]*Profile, error)
}

type didCreator interface {
	PublicDID(method didcreator.Method, verificationMethodType vc.SignatureType, keyType kms.KeyType,
		kc didcreator.KeysCreator) (*didcreator.CreateResult, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

// ServiceConfig configure verifier.Service.
type ServiceConfig struct {
	ProfileStore profileStore
	DIDCreator   didCreator
	KMSRegistry  kmsRegistry
}

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
	presentationDefinitions []*presexch.PresentationDefinition) (*Profile, error) {
	profile.Active = true

	if profile.OIDCConfig != nil {
		keyCreator, err := p.kmsRegistry.GetKeyManager(profile.KMSConfig)
		if err != nil {
			return nil, fmt.Errorf("issuer profile service: create profile failed: get keyCreator %w", err)
		}

		createResult, err := p.didCreator.PublicDID(profile.OIDCConfig.DIDMethod,
			profile.OIDCConfig.ROSigningAlgorithm, profile.OIDCConfig.KeyType, keyCreator)
		if err != nil {
			return nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
		}

		profile.SigningDID = &didcreator.SigningDID{
			DID:            createResult.DocResolution.DIDDocument.ID,
			UpdateKeyURL:   createResult.UpdateKeyURL,
			RecoveryKeyURL: createResult.RecoveryKeyURL,
		}
	}

	id, err := p.store.Create(profile, presentationDefinitions)
	if err != nil {
		return nil, fmt.Errorf("profile service: create profile failed %w", err)
	}

	created, err := p.store.Find(id)
	if err != nil {
		return nil, fmt.Errorf("profile service: create profile failed %w", err)
	}

	return created, nil
}

// Update updates unprotected files with nonempty fields from ProfileUpdate.
func (p *ProfileService) Update(profile *ProfileUpdate) (*Profile, error) {
	err := p.store.Update(profile)
	if err != nil {
		return nil, fmt.Errorf("profile service: update profile failed %w", err)
	}

	updated, err := p.store.Find(profile.ID)
	if err != nil {
		return nil, fmt.Errorf("profile service: create profile failed %w", err)
	}

	return updated, nil
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
