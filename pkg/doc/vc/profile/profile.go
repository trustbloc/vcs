/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	keyPattern       = "%s_%s_%s"
	profileKeyPrefix = "profile"

	credentialStoreName = "credential"

	issuerMode     = "issuer"
	holderMode     = "holder"
	governanceMode = "governance"
)

// New returns new credential recorder instance
func New(provider storage.Provider) (*Profile, error) {
	err := provider.CreateStore(credentialStoreName)
	if err != nil {
		if !errors.Is(err, storage.ErrDuplicateStore) {
			return nil, err
		}
	}

	store, err := provider.OpenStore(credentialStoreName)
	if err != nil {
		return nil, err
	}

	return &Profile{store: store}, nil
}

// Profile takes care of features to be persisted for credentials
type Profile struct {
	store storage.Store
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

// GovernanceProfile struct for governance profile
type GovernanceProfile struct {
	*DataProfile
}

// SaveProfile saves issuer profile to underlying store
func (c *Profile) SaveProfile(data *IssuerProfile) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %s", err.Error())
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
		return fmt.Errorf("save holder profile : %s", err.Error())
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

// SaveGovernanceProfile saves governance profile to the underlying store.
func (c *Profile) SaveGovernanceProfile(data *GovernanceProfile) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save governance profile : %s", err.Error())
	}

	return c.store.Put(getDBKey(governanceMode, data.Name), bytes)
}

// GetGovernanceProfile retrieves the governance profile based on name.
func (c *Profile) GetGovernanceProfile(name string) (*GovernanceProfile, error) {
	bytes, err := c.store.Get(getDBKey(governanceMode, name))
	if err != nil {
		return nil, err
	}

	response := &GovernanceProfile{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func getDBKey(mode, name string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, mode, name)
}
