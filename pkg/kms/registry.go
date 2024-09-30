/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

type Registry struct {
	defaultVCSKeyManager  VCSKeyManager
	defaultConfig         Config
	defaultMetricProvider metricsProvider
}

func NewRegistry(
	defaultVCSKeyManager VCSKeyManager,
	defaultKmsConfig Config,
	defaultMetricProvider metricsProvider,
) *Registry {
	return &Registry{
		defaultConfig:         defaultKmsConfig,
		defaultVCSKeyManager:  defaultVCSKeyManager,
		defaultMetricProvider: defaultMetricProvider,
	}
}

func (r *Registry) GetKeyManager(config *Config) (VCSKeyManager, error) {
	if config == nil {
		return r.defaultVCSKeyManager, nil
	}

	cfgCopy := r.defaultConfig
	cfgCopy.KMSType = config.KMSType

	return NewAriesKeyManager(&cfgCopy, r.defaultMetricProvider)
}
