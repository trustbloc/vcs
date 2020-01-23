/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	keyPattern       = "%s_%s"
	profileKeyPrefix = "profile"
)

// NewProfile returns new credential recorder instance
func NewProfile(store storage.Store) *Profile {
	return &Profile{store: store}
}

// Profile takes care of features to be persisted for credentials
type Profile struct {
	store storage.Store
}

// SaveProfile saves issuer profile to underlying store
func (c *Profile) SaveProfile(profileResponse *ProfileResponse) error {
	k := fmt.Sprintf(keyPattern, profileKeyPrefix, profileResponse.Name)
	bytes, err := json.Marshal(profileResponse)

	if err != nil {
		return fmt.Errorf("save profile marshalling error: %s", err.Error())
	}

	return c.store.Put(k, bytes)
}

// GetProfile returns profile information for given profile name from underlying store
func (c *Profile) GetProfile(name string) (*ProfileResponse, error) {
	k := fmt.Sprintf(keyPattern, profileKeyPrefix, name)

	bytes, err := c.store.Get(k)
	if err != nil {
		return nil, err
	}

	response := &ProfileResponse{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}
