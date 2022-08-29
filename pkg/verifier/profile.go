/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination profile_mocks_test.go -self_package mocks -package verifier_test -source=profile.go -mock_names profileStore=MockProfileStore

package verifier

import (
	"fmt"
)

type ProfileID = string

// Profile verifier profile.
type Profile struct {
	ID             ProfileID   `json:"id"`
	Name           string      `json:"name,omitempty"`
	URL            string      `json:"url,omitempty"`
	Active         bool        `json:"active"`
	Checks         interface{} `json:"checks"`
	OIDCConfig     interface{} `json:"oidcConfig,omitempty"`
	OrganizationID string      `json:"organizationID"`
}

// ProfileUpdate contains only unprotected fields from the verifier profile, that can be changed by update api.
type ProfileUpdate struct {
	ID         ProfileID   `json:"id"`
	Name       string      `json:"name,omitempty"`
	URL        string      `json:"url,omitempty"`
	Checks     interface{} `json:"checks"`
	OIDCConfig interface{} `json:"oidcConfig"`
}

type profileStore interface {
	Create(profile *Profile) (ProfileID, error)
	Update(profile *ProfileUpdate) error
	UpdateActiveField(profileID ProfileID, active bool) error
	Delete(profileID ProfileID) error

	Find(strID ProfileID) (*Profile, error)
	FindByOrgID(orgID string) ([]*Profile, error)
}

// ProfileService manages verifier profile.
type ProfileService struct {
	store profileStore
}

// NewProfileService creates ProfileService.
func NewProfileService(store profileStore) *ProfileService {
	return &ProfileService{store: store}
}

// Create creates and returns profile.
func (p *ProfileService) Create(profile *Profile) (*Profile, error) {
	profile.Active = true

	id, err := p.store.Create(profile)
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
