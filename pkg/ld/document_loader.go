/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"
	ldcontext "github.com/trustbloc/vc-go/ld/context"
	lddocloader "github.com/trustbloc/vc-go/ld/documentloader"
	ldstore "github.com/trustbloc/vc-go/ld/store"
)

// nolint:gochecknoglobals //embedded contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
)

var embedContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
}

// provider contains dependencies for the JSON-LD document loader.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// NewDocumentLoader returns a JSON-LD document loader with preloaded contexts.
func NewDocumentLoader(p provider, opts ...lddocloader.Opts) (jsonld.DocumentLoader, error) {
	loader, err := lddocloader.NewDocumentLoader(p, append(opts, lddocloader.WithExtraContexts(embedContexts...))...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}
