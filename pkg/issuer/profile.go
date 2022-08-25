/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination profile_mocks_test.go -self_package mocks -package issuer_test -source=profile.go -mock_names profileStore=MockProfileStore,didCreator=MockDIDCreator

package issuer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
)

type ProfileID = string

// Profile verifier profile.
type Profile struct {
	ID             ProfileID   `json:"id"`
	Name           string      `json:"name,omitempty"`
	URL            string      `json:"url,omitempty"`
	Active         bool        `json:"active"`
	Checks         interface{} `json:"checks"`
	OIDCConfig     interface{} `json:"oidcConfig"`
	OrganizationID string      `json:"organizationID"`
	VCConfig       *VCConfig   `json:"vcConfig"`
	KMSConfig      *KMSConfig  `json:"kmsConfig"`
}

// ProfileUpdate contains only unprotected fields from the verifier profile, that can be changed by update api.
type ProfileUpdate struct {
	ID         ProfileID   `json:"id"`
	Name       string      `json:"name,omitempty"`
	URL        string      `json:"url,omitempty"`
	Checks     interface{} `json:"checks"`
	OIDCConfig interface{} `json:"oidcConfig"`
	KMSConfig  *KMSConfig  `json:"kmsConfig"`
}

// KMSConfig configure kms that stores signing keys.
type KMSConfig struct {
	KMSType           string `json:"type"`
	Endpoint          string `json:"endpoint"`
	SecretLockKeyPath string `json:"secretLockKeyPath"`
	DBType            string `json:"dbType"`
	DBURL             string `json:"dbURL"`
	DBPrefix          string `json:"dbPrefix"`
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Format           string      `json:"format"`
	SigningAlgorithm string      `json:"signingAlgorithm"`
	KeyType          string      `json:"keyType,omitempty"`
	DIDMethod        string      `json:"didMethod"`
	Status           interface{} `json:"status"`
	Context          []string    `json:"context"`
}

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string
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
	PublicDID(method, verificationMethodType string, keyType kms.KeyType,
		kc didcreator.KeysCreator) (*didcreator.CreateResult, error)
}

// ServiceConfig configure issuer.Service.
type ServiceConfig struct {
	ProfileStore profileStore
	DIDCreator   didCreator

	KeysCreator func(config *KMSConfig) (didcreator.KeysCreator, error)
}

// ProfileService manages verifier profile.
type ProfileService struct {
	store       profileStore
	didCreator  didCreator
	keysCreator func(config *KMSConfig) (didcreator.KeysCreator, error)
}

// NewProfileService creates ProfileService.
func NewProfileService(config *ServiceConfig) *ProfileService {
	return &ProfileService{
		store:       config.ProfileStore,
		didCreator:  config.DIDCreator,
		keysCreator: config.KeysCreator,
	}
}

// Create creates and returns profile.
func (p *ProfileService) Create(profile *Profile, credentialManifests []*cm.CredentialManifest) (*Profile, error) {
	profile.Active = true

	signingAlgorithm, err := vc.ValidateVCSignatureAlgorithm(profile.VCConfig.Format, profile.VCConfig.SigningAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	keyType, err := vc.ValidateSignatureKeyType(signingAlgorithm, profile.VCConfig.KeyType)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	kms, err := p.keysCreator(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed: get kms %w", err)
	}

	createResult, err := p.didCreator.PublicDID(profile.VCConfig.DIDMethod,
		profile.VCConfig.SigningAlgorithm, keyType, kms)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
	}

	id, err := p.store.Create(profile, &SigningDID{
		DID:            createResult.DocResolution.DIDDocument.ID,
		UpdateKeyURL:   createResult.UpdateKeyURL,
		RecoveryKeyURL: createResult.RecoveryKeyURL,
	}, credentialManifests)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	created, _, err := p.store.Find(id)
	if err != nil {
		return nil, fmt.Errorf("issuer profile service: create profile failed %w", err)
	}

	return created, nil
}

// Update updates unprotected files with nonempty fields from ProfileUpdate.
func (p *ProfileService) Update(profile *ProfileUpdate) (*Profile, error) {
	err := p.store.Update(profile)
	if err != nil {
		return nil, fmt.Errorf("profile service: update profile failed %w", err)
	}

	updated, _, err := p.store.Find(profile.ID)
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
	profile, _, err := p.store.Find(profileID)
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
