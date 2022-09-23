/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
)

type Registry struct {
	defaultVCSKeyManager VCSKeyManager
}

func NewRegistry(defaultVCSKeyManager VCSKeyManager) *Registry {
	return &Registry{
		defaultVCSKeyManager: defaultVCSKeyManager,
	}
}

func (r *Registry) GetKeyManager(config *Config) (VCSKeyManager, error) {
	if config == nil {
		return r.defaultVCSKeyManager, nil
	}

	// TODO handle kms per profile creation
	return nil, fmt.Errorf("unsupported profile kms")
}
