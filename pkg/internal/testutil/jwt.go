/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/signature/suite"
	"github.com/trustbloc/vc-go/verifiable"
)

type SignedClaimsJWTResult struct {
	JWT               string
	VDR               vdrapi.Registry
	Signer            api.FixedKeySigner
	VerMethodDIDKeyID string
}

func SignedClaimsJWT(t *testing.T, claims interface{}) *SignedClaimsJWTResult {
	t.Helper()

	customKMS := createKMS(t)

	kc, err := customKMS.KMSCrypto()
	require.NoError(t, err)

	pk, err := kc.Create(kms.ED25519Type)
	require.NoError(t, err)

	fks, err := kc.FixedKeySigner(pk)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", pk.KeyID, pk)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	token, err := jwt.NewSigned(claims, jose.Headers{
		jose.HeaderKeyID: didDoc.VerificationMethod[0].ID,
	}, verifiable.GetJWTSigner(suite.NewCryptoWrapperSigner(fks), algName))
	require.NoError(t, err)

	jws, err := token.Serialize(false)
	require.NoError(t, err)

	return &SignedClaimsJWTResult{
		JWT: jws,
		VDR: &vdrmock.VDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		Signer:            fks,
		VerMethodDIDKeyID: didDoc.VerificationMethod[0].ID,
	}
}

func SignedClaimsJWTWithExistingPrivateKey(
	t *testing.T, verMethodDIDKeyID string, signer api.FixedKeySigner, claims interface{}) string {
	t.Helper()

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	token, err := jwt.NewSigned(claims, jose.Headers{
		jose.HeaderKeyID: verMethodDIDKeyID,
	}, verifiable.GetJWTSigner(suite.NewCryptoWrapperSigner(signer), algName))
	require.NoError(t, err)

	jws, err := token.Serialize(false)
	require.NoError(t, err)

	return jws
}
