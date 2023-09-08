/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/did/endpoint"
	jsonld "github.com/trustbloc/did-go/doc/ld/processor"
	ariesmockstorage "github.com/trustbloc/did-go/legacy/mock/storage"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/kms/localkms"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmskeytypes "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/signature/suite"
	"github.com/trustbloc/vc-go/signature/suite/jsonwebsignature2020"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/jws"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

// SignedVC returns signed VC represented by vcBytes.
func SignedVC(
	t *testing.T,
	vcBytes []byte,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	sf vcsverifiable.Format,
	loader ld.DocumentLoader,
	purpose string,
	isSDJWT bool,
) (*verifiable.Credential, vdrapi.Registry) {
	t.Helper()

	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	return proveVC(t, vc, kt, sr, sf, loader, purpose, isSDJWT)
}

func proveVC(
	t *testing.T,
	credential *verifiable.Credential,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	sf vcsverifiable.Format,
	loader ld.DocumentLoader,
	purpose string,
	isSDJWT bool,
) (*verifiable.Credential, vdrapi.Registry) {
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
	case vcsverifiable.Ldp:
		signerSuite := jsonwebsignature2020.New(
			suite.WithSigner(suite.NewCryptoSigner(customCrypto, kh)))
		err = credential.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "JsonWebSignature2020",
			Suite:                   signerSuite,
			SignatureRepresentation: sr,
			Created:                 &created,
			VerificationMethod:      didDoc.VerificationMethod[0].ID,
			Challenge:               "challenge",
			Domain:                  "domain",
			Purpose:                 purpose,
		}, jsonld.WithDocumentLoader(loader))
		require.NoError(t, err)
	case vcsverifiable.Jwt:
		claims, err := credential.JWTClaims(false)
		require.NoError(t, err)

		jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kt)
		require.NoError(t, err)

		if isSDJWT {
			jwsAlgName, err := jwsAlgo.Name()
			require.NoError(t, err)

			joseSigner := jws.NewSigner(didDoc.VerificationMethod[0].ID, jwsAlgName, suite.NewCryptoSigner(customCrypto, kh))

			sdjwtCredential, err := credential.MakeSDJWT(joseSigner, didDoc.VerificationMethod[0].ID)
			require.NoError(t, err)

			vcParsed, err := verifiable.ParseCredential([]byte(sdjwtCredential),
				verifiable.WithDisabledProofCheck(),
				verifiable.WithJSONLDDocumentLoader(loader))
			require.NoError(t, err)

			credential = vcParsed
		} else {
			jws, err := claims.MarshalJWS(jwsAlgo, suite.NewCryptoSigner(customCrypto, kh), didDoc.VerificationMethod[0].ID)
			require.NoError(t, err)

			credential.JWT = jws
		}
	}

	return credential, &vdrmock.VDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return &did.DocResolution{DIDDocument: didDoc}, nil
		},
	}
}

func createDIDDoc(t *testing.T, didID, keyID string, pubKeyBytes []byte, kt kmskeytypes.KeyType) *did.Doc {
	t.Helper()

	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "JsonWebKey2020"
	)

	creator := fmt.Sprintf("%s#%s", didID, keyID)

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	j, _ := jwksupport.PubKeyBytesToJWK(pubKeyBytes, kt)

	mv, _ := did.NewVerificationMethodFromJWK(creator, keyType, "", j)

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{*mv},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: *mv}},
		Authentication:       []did.Verification{{VerificationMethod: *mv}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: *mv}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: *mv}},
	}
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}
