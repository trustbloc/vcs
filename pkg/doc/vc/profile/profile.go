/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	keyPattern       = "%s_%s_%s"
	profileKeyPrefix = "profile"

	credentialStoreName = "credential"

	issuerMode = "issuer"
	holderMode = "holder"
)

// New returns new credential recorder instance
func New(provider ariesstorage.Provider) (*Profile, error) {
	store, err := provider.OpenStore(credentialStoreName)
	if err != nil {
		return nil, err
	}

	return &Profile{store: store}, nil
}

// Profile takes care of features to be persisted for credentials
type Profile struct {
	store ariesstorage.Store
}

// DataProfile base profile
type DataProfile struct {
	Name                    string                             `json:"name"`
	DID                     string                             `json:"did"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	Creator                 string                             `json:"creator"`
	Created                 *time.Time                         `json:"created"`
}

// IssuerProfile struct for issuer profile
type IssuerProfile struct {
	URI             string          `json:"uri"`
	EDVVaultID      string          `json:"edvVaultID"`
	DisableVCStatus bool            `json:"disableVCStatus"`
	OverwriteIssuer bool            `json:"overwriteIssuer"`
	EDVCapability   json.RawMessage `json:"edvCapability,omitempty"`
	EDVController   string          `json:"edvController"`
	*DataProfile
}

// HolderProfile struct for holder profile
type HolderProfile struct {
	OverwriteHolder bool `json:"overwriteHolder,omitempty"`
	*DataProfile
}

// SaveProfile saves issuer profile to underlying store
func (c *Profile) SaveProfile(data *IssuerProfile) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %w", err)
	}

	return c.store.Put(getDBKey(issuerMode, data.Name), bytes)
}

// GetProfile returns profile information for given profile name from underlying store
func (c *Profile) GetProfile(name string) (*IssuerProfile, error) {
	bytes, err := c.store.Get(getDBKey(issuerMode, name))
	if err != nil {
		return nil, err
	}

	response := &IssuerProfile{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// DeleteProfile deletes the profile from the underlying store.
func (c *Profile) DeleteProfile(name string) error {
	return c.store.Delete(getDBKey(issuerMode, name))
}

// SaveHolderProfile saves holder profile to the underlying store.
func (c *Profile) SaveHolderProfile(data *HolderProfile) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save holder profile : %w", err)
	}

	return c.store.Put(getDBKey(holderMode, data.Name), bytes)
}

// GetHolderProfile retrieves the holder profile based on name.
func (c *Profile) GetHolderProfile(name string) (*HolderProfile, error) {
	bytes, err := c.store.Get(getDBKey(holderMode, name))
	if err != nil {
		return nil, err
	}

	response := &HolderProfile{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// DeleteHolderProfile deletes the holder profile from the underlying store.
func (c *Profile) DeleteHolderProfile(name string) error {
	return c.store.Delete(getDBKey(holderMode, name))
}

func getDBKey(mode, name string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, mode, name)
}
