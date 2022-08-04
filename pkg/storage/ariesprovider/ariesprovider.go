/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider

import "github.com/hyperledger/aries-framework-go/spi/storage"

// AriesVCSProvider is a generic VCS storage provider that works with any Aries storage.Provider implementation.
// It's functional but not as optimized as other VCS provider implementations.
type AriesVCSProvider struct {
	provider storage.Provider
}

func New(provider storage.Provider) *AriesVCSProvider {
	return &AriesVCSProvider{provider: provider}
}

// GetAriesProvider returns a storage provider implementing the Aries storage interface for use with Aries library
// calls.
func (a *AriesVCSProvider) GetAriesProvider() storage.Provider {
	return a.provider
}
