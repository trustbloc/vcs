/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	keyPattern       = "%s_%s"
	profileKeyPrefix = "profile"
)

// New returns new credential recorder instance
func New(store storage.Store) *Profile {
	return &Profile{store: store}
}

// Profile takes care of features to be persisted for credentials
type Profile struct {
	store storage.Store
}

// DataProfile struct for profile
type DataProfile struct {
	Name          string     `json:"name"`
	DID           string     `json:"did"`
	URI           string     `json:"uri"`
	SignatureType string     `json:"signatureType"`
	Creator       string     `json:"creator"`
	Created       *time.Time `json:"created"`
}

// SaveProfile saves issuer profile to underlying store
func (c *Profile) SaveProfile(data *DataProfile) error {
	k := fmt.Sprintf(keyPattern, profileKeyPrefix, data.Name)

	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("save profile marshalling error: %s", err.Error())
	}

	return c.store.Put(k, bytes)
}

// GetProfile returns profile information for given profile name from underlying store
func (c *Profile) GetProfile(name string) (*DataProfile, error) {
	k := fmt.Sprintf(keyPattern, profileKeyPrefix, name)

	bytes, err := c.store.Get(k)
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
