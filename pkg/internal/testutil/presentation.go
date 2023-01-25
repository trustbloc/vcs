/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

// SignedVP returns signed Presentation represented by vpBytes.
func SignedVP(
	t *testing.T,
	vpBytes []byte,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	sf vcs.Format,
	loader ld.DocumentLoader,
	proofPurpose string,
) (*verifiable.Presentation, vdrapi.Registry) {
	t.Helper()

	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	mockVDRRegistry := proveVP(t, vp, kt, sr, sf, loader, proofPurpose)

	return vp, mockVDRRegistry
}

func proveVP(
	t *testing.T,
	presentation *verifiable.Presentation,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	sf vcs.Format,
	loader ld.DocumentLoader,
	proofPurpose string,
) vdrapi.Registry {
	t.Helper()

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	keyID, kh, err := customKMS.Create(kt)
	require.NoError(t, err)

	pkBytes, _, err := customKMS.ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", keyID, pkBytes, kt)

	// Sign
	switch sf {
	case vcs.Ldp:
		signerSuite := jsonwebsignature2020.New(
			suite.WithSigner(suite.NewCryptoSigner(customCrypto, kh)))
		err = presentation.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "JsonWebSignature2020",
			Suite:                   signerSuite,
			SignatureRepresentation: sr,
			Created:                 &created,
			VerificationMethod:      didDoc.VerificationMethod[0].ID,
			Challenge:               "challenge",
			Domain:                  "domain",
			Purpose:                 proofPurpose,
		}, jsonld.WithDocumentLoader(loader))
		require.NoError(t, err)
	case vcs.Jwt:
		claims, err := presentation.JWTClaims([]string{}, false)
		require.NoError(t, err)

		jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kt)
		require.NoError(t, err)

		jws, err := claims.MarshalJWS(jwsAlgo, suite.NewCryptoSigner(customCrypto, kh), keyID)
		require.NoError(t, err)

		presentation.JWT = jws
	}

	return &vdrmock.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return &did.DocResolution{DIDDocument: didDoc}, nil
		},
	}
}
