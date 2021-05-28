/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

// nolint:gochecknoglobals //embedded contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/governance.jsonld
	governanceVocab []byte
)

var embedContexts = []jsonld.ContextDocument{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
		Content: governanceVocab,
	},
}

// DocumentLoader returns a JSON-LD document loader with preloaded contexts.
func DocumentLoader(storageProvider storage.Provider) (ld.DocumentLoader, error) {
	loader, err := jsonld.NewDocumentLoader(storageProvider, jsonld.WithExtraContexts(embedContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
