/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
)

type ariesServices struct {
	storageProvider   storage.Provider
	vdrRegistry       vdrapi.Registry
	suite             api.Suite
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

func (p *ariesServices) Suite() api.Suite {
	return p.suite
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
