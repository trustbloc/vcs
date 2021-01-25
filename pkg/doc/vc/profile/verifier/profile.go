/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"fmt"

	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyPattern       = "%s_%s"
	profileKeyPrefix = "profile"

	storeName = "verifier"
)

// Profile db operation
type Profile struct {
	store ariesstorage.Store
}

// ProfileData struct for profile
type ProfileData struct {
	ID                 string   `json:"id,omitempty"`
	Name               string   `json:"name"`
	CredentialChecks   []string `json:"credentialChecks,omitempty"`
	PresentationChecks []string `json:"presentationChecks,omitempty"`
}

// New returns new credential recorder instance
func New(provider ariesstorage.Provider) (*Profile, error) {
	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &Profile{store: store}, nil
}

// SaveProfile saves the profile data.
func (c *Profile) SaveProfile(data *ProfileData) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("verifier profile save - marshalling error: %s", err.Error())
	}

	return c.store.Put(getDBKey(data.ID), bytes)
}

// GetProfile retrieves the profile data based on id.
func (c *Profile) GetProfile(id string) (*ProfileData, error) {
	bytes, err := c.store.Get(getDBKey(id))
	if err != nil {
		return nil, err
	}

	response := &ProfileData{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// DeleteProfile deletes the verifier profile from underlying store
func (c *Profile) DeleteProfile(name string) error {
	return c.store.Delete(getDBKey(name))
}

func getDBKey(id string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, id)
}
