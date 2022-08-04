/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbprovider

import (
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesspi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// MongoDBVCSProvider is an optimized VCS storage provider that only works with MongoDB.
type MongoDBVCSProvider struct {
	provider *mongodb.Provider
}

func New(mongoDBProvider *mongodb.Provider) *MongoDBVCSProvider {
	return &MongoDBVCSProvider{provider: mongoDBProvider}
}

// GetAriesProvider returns a storage provider implementing the Aries storage interface for use with Aries library
// calls.
func (m *MongoDBVCSProvider) GetAriesProvider() ariesspi.Provider {
	return m.provider
}
