/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

// SignedVP returns signed VP represented by vpBytes.
func SignedVP(
	t *testing.T,
	vpBytes []byte,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	loader ld.DocumentLoader,
	proofPurpose string,
) (*verifiable.Presentation, vdrapi.Registry) {
	t.Helper()

	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	mockVDRRegistry := prove(t, vp, kt, sr, loader, proofPurpose)

	return vp, mockVDRRegistry
}
