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

	issuerMode = "issuer"
	holderMode = "holder"
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

// DataProfile struct for profile
type DataProfile struct {
	Name                    string                             `json:"name"`
	DID                     string                             `json:"did"`
	URI                     string                             `json:"uri"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	Creator                 string                             `json:"creator"`
	Created                 *time.Time                         `json:"created"`
	DisableVCStatus         bool                               `json:"disableVCStatus"`
	OverwriteIssuer         bool                               `json:"overwriteIssuer"`
}

// HolderProfile struct for holder profile
type HolderProfile struct {
	Name                    string                             `json:"name"`
	DID                     string                             `json:"did"`
	SignatureType           string                             `json:"signatureType"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	Creator                 string                             `json:"creator"`
	OverwriteHolder         bool                               `json:"overwriteHolder,omitempty"`
	Created                 *time.Time                         `json:"created"`
}

// SaveProfile saves issuer profile to underlying store
func (c *Profile) SaveProfile(data *DataProfile) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %s", err.Error())
	}

	return c.store.Put(getDBKey(issuerMode, data.Name), bytes)
}

// GetProfile returns profile information for given profile name from underlying store
func (c *Profile) GetProfile(name string) (*DataProfile, error) {
	bytes, err := c.store.Get(getDBKey(issuerMode, name))
	if err != nil {
		return nil, err
	}

	response := &DataProfile{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
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

func getDBKey(mode, name string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, mode, name)
}
