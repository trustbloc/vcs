/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	jsonld "github.com/trustbloc/did-go/doc/ld/processor"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"

	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type SignedPresentationResult struct {
	Presentation      *verifiable.Presentation
	VDR               vdrapi.Registry
	Kh                *jwk.JWK
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

	kc, err := customKMS.KMSCrypto()
	require.NoError(t, err)

	pk, err := kc.Create(kms.ED25519Type)
	require.NoError(t, err)

	fks, err := kc.FixedKeySigner(pk)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", pk.KeyID, pk)

	// Sign
	switch format {
	case vcs.Ldp:
		addLDP(t, presentation, didDoc.VerificationMethod[0].ID, fks, kms.ED25519Type, opts...)
	case vcs.Jwt:
		signJWS(t, presentation, didDoc.VerificationMethod[0].ID, fks)
	}

	return &SignedPresentationResult{
		Presentation: presentation,
		VDR: &vdrmock.VDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		Kh:                pk,
		VerMethodDIDKeyID: didDoc.VerificationMethod[0].ID,
	}
}

// SignedVPWithExistingPrivateKey returns signed presentation using kh.
func SignedVPWithExistingPrivateKey(
	t *testing.T,
	presentation *verifiable.Presentation,
	format vcs.Format,
	verMethodDIDKeyID string,
	keyType kms.KeyType,
	signer api.FixedKeySigner,
	opts ...LDPOpt,
) *verifiable.Presentation {
	t.Helper()

	return proveVPWithExistingPrivateKey(
		t, presentation, format, verMethodDIDKeyID, keyType, signer, opts...)
}

func proveVPWithExistingPrivateKey(
	t *testing.T,
	presentation *verifiable.Presentation,
	format vcs.Format,
	verMethodDIDKeyID string,
	keyType kms.KeyType,
	signer api.FixedKeySigner,
	opts ...LDPOpt,
) *verifiable.Presentation {
	t.Helper()

	// Sign
	switch format {
	case vcs.Ldp:
		addLDP(t, presentation, verMethodDIDKeyID, signer, keyType, opts...)
	case vcs.Jwt:
		signJWS(t, presentation, verMethodDIDKeyID, signer)
	}

	return presentation
}

func signJWS(
	t *testing.T,
	presentation *verifiable.Presentation,
	keyID string,
	fks api.FixedKeySigner,
) {
	t.Helper()

	claims, err := presentation.JWTClaims([]string{}, false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, testsupport.NewProofCreator(fks), keyID)
	require.NoError(t, err)

	presentation.JWT = jws
}

func addLDP(
	t *testing.T,
	presentation *verifiable.Presentation,
	keyID string,
	fks api.FixedKeySigner,
	keyType kms.KeyType,
	opts ...LDPOpt,
) {
	t.Helper()

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	ctx := &verifiable.LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		KeyType:                 keyType,
		ProofCreator:            testsupport.NewProofCreator(fks),
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
