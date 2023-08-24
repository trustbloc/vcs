/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldutil

import (
	_ "embed"
	"fmt"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ld "github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
)

// nolint:gochecknoglobals //embedded test contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocab []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
	//go:embed contexts/revocation-list-2021.jsonld
	revocationList2021 []byte
)

var extraContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld", // resolvable
		Content:     citizenshipVocab,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: examplesVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		Content: examplesExtVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-crude-product-v1.jsonld",
		Content: examplesCrudeProductVocab,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
	{
		URL:         "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld",
		DocumentURL: "https://raw.githubusercontent.com/w3c-ccg/vc-status-list-2021/343b8b59cddba4525e1ef355356ae760fc75904e/contexts/v1.jsonld",
		Content:     revocationList2021,
	},
}

// DocumentLoader returns a JSON-LD document loader with preloaded test contexts.
func DocumentLoader() (*ld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := ld.NewDocumentLoader(ldStore, ld.WithExtraContexts(extraContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}
