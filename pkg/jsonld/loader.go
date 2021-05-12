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
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocab []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/w3id-vaccination-v1.jsonld
	vaccinationVocab []byte
	//go:embed contexts/booking-reference-v1.jsonld
	bookingRefVocab []byte
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
	// TODO: Add contexts below thru API in BDD tests (requires AFGO #2730)
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
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
	// Added for supporting sandbox flows. TODO: Remove after implementing AFGO #2730.
	{
		URL:         "https://w3id.org/vaccination/v1",
		DocumentURL: "https://w3c-ccg.github.io/vaccination-vocab/context/v1/index.json",
		Content:     vaccinationVocab,
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/examples/booking-ref-v1.jsonld",
		DocumentURL: "",
		Content:     bookingRefVocab,
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
