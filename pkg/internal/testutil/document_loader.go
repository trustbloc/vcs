/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	_ "embed" //nolint:gci // required for go:embed
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

// nolint:gochecknoglobals // embedded test contexts
var (
	//go:embed contexts/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed contexts/examples_v1.jsonld
	vcExamples []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
	//go:embed contexts/citizenship_v1.jsonld
	citizenship []byte
	//go:embed contexts/governance.jsonld
	governance []byte
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020 []byte
)

// DocumentLoader returns a document loader with preloaded test contexts.
func DocumentLoader(t *testing.T) *jsonld.DocumentLoader {
	t.Helper()

	loader, err := jsonld.NewDocumentLoader(ariesmockstorage.NewMockStoreProvider(),
		jsonld.WithExtraContexts(
			jsonld.ContextDocument{
				URL:     "https://www.w3.org/2018/credentials/examples/v1",
				Content: credentialExamples,
			},
			jsonld.ContextDocument{
				URL:     "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
				Content: vcExamples,
			},
			jsonld.ContextDocument{
				URL:     "https://www.w3.org/ns/odrl.jsonld",
				Content: odrl,
			},
			jsonld.ContextDocument{
				URL:         "https://w3id.org/citizenship/v1",
				DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
				Content:     citizenship,
			},
			jsonld.ContextDocument{
				URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
				Content: governance,
			},
			jsonld.ContextDocument{
				URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
				Content: jws2020,
			},
		),
	)
	require.NoError(t, err)

	return loader
}
