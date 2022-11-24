/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

type ariesServices struct {
	storageProvider   storage.Provider
	vdrRegistry       vdrapi.Registry
	crypto            crypto.Crypto
	kms               kms.KeyManager
	documentLoader    jsonld.DocumentLoader
	mediaTypeProfiles []string
}

func (p *ariesServices) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p *ariesServices) SetStorageProvider(sp storage.Provider) {
	p.storageProvider = sp
}

func (p *ariesServices) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *ariesServices) Crypto() crypto.Crypto {
	return p.crypto
}

func (p *ariesServices) KMS() kms.KeyManager {
	return p.kms
}

func (p *ariesServices) JSONLDDocumentLoader() jsonld.DocumentLoader {
	return p.documentLoader
}

func (p *ariesServices) MediaTypeProfiles() []string {
	return p.mediaTypeProfiles
}

// Close frees resources being maintained by the framework.
func (p *ariesServices) Close() error {
	if p.storageProvider != nil {
		err := p.storageProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	if p.vdrRegistry != nil {
		if err := p.vdrRegistry.Close(); err != nil {
			return fmt.Errorf("vdr registry close failed: %w", err)
		}
	}

	return nil
}
