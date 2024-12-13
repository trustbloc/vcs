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
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmskeytypes "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"

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

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	kc, err := customKMS.KMSCrypto()
	require.NoError(t, err)

	pk, err := kc.Create(kt)
	require.NoError(t, err)

	fks, err := kc.FixedKeySigner(pk)
	require.NoError(t, err)

	didDoc := createDIDDoc(t, "did:trustblock:abc", pk.KeyID, pk)

	proofCreator := testsupport.NewProofCreator(fks)

	// Sign
	switch sf {
	case vcsverifiable.Ldp:
		err = credential.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "JsonWebSignature2020",
			KeyType:                 kt,
			ProofCreator:            proofCreator,
			SignatureRepresentation: sr,
			Created:                 &created,
			VerificationMethod:      didDoc.VerificationMethod[0].ID,
			Challenge:               "challenge",
			Domain:                  "domain",
			Purpose:                 purpose,
		}, jsonld.WithDocumentLoader(loader))
		require.NoError(t, err)
	case vcsverifiable.Cwt:
		cwtAlgo, cwtErr := verifiable.KeyTypeToCWSAlgo(kt)
		require.NoError(t, cwtErr)

		credential, err = credential.CreateSignedCOSEVC(cwtAlgo, proofCreator, didDoc.VerificationMethod[0].ID)
		require.NoError(t, err)
	case vcsverifiable.Jwt:
		jwsAlgo, jwtErr := verifiable.KeyTypeToJWSAlgo(kt)
		require.NoError(t, jwtErr)

		if isSDJWT {
			jwsAlgName, sdErr := jwsAlgo.Name()
			require.NoError(t, sdErr)

			joseSigner, sdErr := jwt.NewJOSESigner(
				jwt.SignParameters{
					KeyID:             didDoc.VerificationMethod[0].ID,
					JWTAlg:            jwsAlgName,
					AdditionalHeaders: nil,
				}, proofCreator)
			require.NoError(t, sdErr)

			sdjwtCredential, sdErr := credential.MakeSDJWT(joseSigner, didDoc.VerificationMethod[0].ID,
				verifiable.MakeSDJWTWithNonSelectivelyDisclosableClaims([]string{"id", "type", "@type"}),
			)
			require.NoError(t, sdErr)

			vcParsed, sdErr := verifiable.ParseCredential([]byte(sdjwtCredential),
				verifiable.WithDisabledProofCheck(),
				verifiable.WithJSONLDDocumentLoader(loader))
			require.NoError(t, sdErr)

			credential = vcParsed
		} else {
			credential, jwtErr = credential.CreateSignedJWTVC(
				false, jwsAlgo, proofCreator, didDoc.VerificationMethod[0].ID)
			require.NoError(t, jwtErr)
		}
	}

	return credential, &vdrmock.VDRegistry{
		ResolveFunc: func(_ string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return &did.DocResolution{DIDDocument: didDoc}, nil
		},
	}
}

func createDIDDoc(t *testing.T, didID, keyID string, pubJWK *jwk.JWK) *did.Doc {
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

	mv, _ := did.NewVerificationMethodFromJWK(creator, keyType, "", pubJWK)

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

func createKMS(t *testing.T) api.Suite {
	t.Helper()

	storeProv, err := kms.NewAriesProviderWrapper(ariesmockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	cryptoSuite, err := localsuite.NewLocalCryptoSuite(
		"local-lock://custom/primary/key/",
		storeProv,
		&noop.NoLock{},
	)
	require.NoError(t, err)

	return cryptoSuite
}
