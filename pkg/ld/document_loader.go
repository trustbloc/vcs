/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
)

// nolint:gochecknoglobals //embedded contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/governance.jsonld
	governanceVocab []byte
)

var embedContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
		Content: governanceVocab,
	},
}

// provider contains dependencies for the JSON-LD document loader.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// NewDocumentLoader returns a JSON-LD document loader with preloaded contexts.
func NewDocumentLoader(p provider, opts ...ld.DocumentLoaderOpts) (jsonld.DocumentLoader, error) {
	loader, err := ld.NewDocumentLoader(p, append(opts, ld.WithExtraContexts(embedContexts...))...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}
