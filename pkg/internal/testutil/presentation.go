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
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"

	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type SignedPresentationResult struct {
	Presentation      *verifiable.Presentation
	VDR               vdrapi.Registry
	Kh                interface{}
	VerMethodDIDKeyID string
}

type LDPOpt func(ldpc *verifiable.LinkedDataProofContext)

func WithChallenge(challenge string) LDPOpt {
	return func(ldpc *verifiable.LinkedDataProofContext) {
		ldpc.Challenge = challenge
	}
}

func WithDomain(domain string) LDPOpt {
	return func(ldpc *verifiable.LinkedDataProofContext) {
		ldpc.Domain = domain
	}
}

// SignedVP returns signed Presentation represented by vpBytes.
func SignedVP(
	t *testing.T,
	vpBytes []byte,
	format vcs.Format,
	opts ...LDPOpt,
) *SignedPresentationResult {
	t.Helper()

	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(DocumentLoader(t)))
	require.NoError(t, err)

	return proveVP(t, vp, format, opts...)
}

func proveVP(
	t *testing.T,
	presentation *verifiable.Presentation,
	format vcs.Format,
	opts ...LDPOpt,
) *SignedPresentationResult {
	t.Helper()

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	keyID, kh, err := customKMS.Create(kms.ED25519Type)
	require.NoError(t, err)

	pkBytes, _, err := customKMS.ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", keyID, pkBytes, kms.ED25519Type)

	// Sign
	switch format {
	case vcs.Ldp:
		addLDP(t, presentation, didDoc.VerificationMethod[0].ID, customCrypto, kh, opts...)
	case vcs.Jwt:
		signJWS(t, presentation, didDoc.VerificationMethod[0].ID, customCrypto, kh)
	}

	return &SignedPresentationResult{
		Presentation: presentation,
		VDR: &vdrmock.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		Kh:                kh,
		VerMethodDIDKeyID: didDoc.VerificationMethod[0].ID,
	}
}

// SignedVPWithExistingPrivateKey returns signed presentation using kh.
func SignedVPWithExistingPrivateKey(
	t *testing.T,
	presentation *verifiable.Presentation,
	format vcs.Format,
	verMethodDIDKeyID string,
	kh interface{},
	opts ...LDPOpt,
) *verifiable.Presentation {
	t.Helper()

	return proveVPWithExistingPrivateKey(
		t, presentation, format, verMethodDIDKeyID, kh, opts...)
}

func proveVPWithExistingPrivateKey(
	t *testing.T,
	presentation *verifiable.Presentation,
	format vcs.Format,
	verMethodDIDKeyID string,
	kh interface{},
	opts ...LDPOpt,
) *verifiable.Presentation {
	t.Helper()

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	// Sign
	switch format {
	case vcs.Ldp:
		addLDP(t, presentation, verMethodDIDKeyID, customCrypto, kh, opts...)
	case vcs.Jwt:
		signJWS(t, presentation, verMethodDIDKeyID, customCrypto, kh)
	}

	return presentation
}

func signJWS(
	t *testing.T,
	presentation *verifiable.Presentation,
	keyID string,
	customCrypto *tinkcrypto.Crypto,
	kh interface{},
) {
	t.Helper()

	claims, err := presentation.JWTClaims([]string{}, false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, suite.NewCryptoSigner(customCrypto, kh), keyID)
	require.NoError(t, err)

	presentation.JWT = jws
}

func addLDP(
	t *testing.T,
	presentation *verifiable.Presentation,
	keyID string,
	customCrypto *tinkcrypto.Crypto,
	kh interface{},
	opts ...LDPOpt,
) {
	t.Helper()

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	signerSuite := jsonwebsignature2020.New(
		suite.WithSigner(suite.NewCryptoSigner(customCrypto, kh)))

	ctx := &verifiable.LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		Suite:                   signerSuite,
		SignatureRepresentation: verifiable.SignatureProofValue,
		Created:                 &created,
		VerificationMethod:      keyID,
		Purpose:                 "assertionMethod",
	}

	defaultOpts := []LDPOpt{WithChallenge("challenge"), WithDomain("domain")}

	if opts != nil {
		defaultOpts = opts
	}

	for _, f := range defaultOpts {
		f(ctx)
	}

	err = presentation.AddLinkedDataProof(ctx, jsonld.WithDocumentLoader(DocumentLoader(t)))
	require.NoError(t, err)
}
