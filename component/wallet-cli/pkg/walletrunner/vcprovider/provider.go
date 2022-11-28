/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcprovider

import (
	"crypto/tls"
	"fmt"
)

// VCProvider represents the API for credentials provider.
type VCProvider interface {
	// GetConfig returns *Config.
	GetConfig() *Config
	// GetCredentials returns the map of signed credentials.
	GetCredentials() (map[string][]byte, error)
}

type Config struct {
	TLS                 *tls.Config
	WalletParams        *WalletParams
	UniResolverURL      string
	ContextProviderURL  string
	OidcProviderURL     string
	IssueVCURL          string
	DidDomain           string
	DidServiceAuthToken string
	VCFormat            string
	OrgName             string
	OrgSecret           string
	Debug               bool
}

type WalletParams struct {
	Token      string
	Passphrase string
	UserID     string
	DidID      string
	DidKeyID   string
}

type ConfigOption func(c *Config)

func GetProvider(vcProviderType string, opts ...ConfigOption) (VCProvider, error) {
	switch vcProviderType {
	case ProviderVCS:
		return newVCSCredentialsProvider(opts...), nil
	default:
		return nil, fmt.Errorf("unsupported vc provider type %s", vcProviderType)
	}
}
