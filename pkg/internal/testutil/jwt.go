/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/did"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/signature/suite"
	"github.com/trustbloc/vc-go/verifiable"
)

type SignedClaimsJWTResult struct {
	JWT               string
	VDR               vdrapi.Registry
	Kh                interface{}
	VerMethodDIDKeyID string
}

func SignedClaimsJWT(t *testing.T, claims interface{}) *SignedClaimsJWTResult {
	t.Helper()

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	keyID, kh, err := customKMS.Create(kms.ED25519Type)
	require.NoError(t, err)

	pkBytes, _, err := customKMS.ExportPubKeyBytes(keyID)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", keyID, pkBytes, kms.ED25519Type)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	token, err := jwt.NewSigned(claims, jose.Headers{
		jose.HeaderKeyID: didDoc.VerificationMethod[0].ID,
	}, verifiable.GetJWTSigner(suite.NewCryptoSigner(customCrypto, kh), algName))
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
		Kh:                kh,
		VerMethodDIDKeyID: didDoc.VerificationMethod[0].ID,
	}
}

func SignedClaimsJWTWithExistingPrivateKey(
	t *testing.T, verMethodDIDKeyID string, kh interface{}, claims interface{}) string {
	t.Helper()

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	algName, err := jwsAlgo.Name()
	require.NoError(t, err)

	token, err := jwt.NewSigned(claims, jose.Headers{
		jose.HeaderKeyID: verMethodDIDKeyID,
	}, verifiable.GetJWTSigner(suite.NewCryptoSigner(customCrypto, kh), algName))
	require.NoError(t, err)

	jws, err := token.Serialize(false)
	require.NoError(t, err)

	return jws
}
