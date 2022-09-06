/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import "fmt"

type Registry struct {
	defaultCfg *Config
}

func NewRegistry(defaultCfg *Config) *Registry {
	return &Registry{
		defaultCfg: defaultCfg,
	}
}

func (r *Registry) GetKeyManager(config *Config) (VCSKeyManager, error) {
	if config == nil {
		config = r.defaultCfg
	}

	if config.KMSType == Local {
		return NewLocalKeyManager(config)
	}

	return nil, fmt.Errorf("unsupported kms type %q", config.KMSType)
}
