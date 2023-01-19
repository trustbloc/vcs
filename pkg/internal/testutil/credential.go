/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

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
	disclosures ...string,
) (*verifiable.Credential, vdrapi.Registry) {
	t.Helper()

	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	mockVDRRegistry := proveVC(t, vc, kt, sr, sf, loader, purpose)

	if len(disclosures) > 0 && sf == vcsverifiable.Jwt {
		vc.JWT += common.CombinedFormatSeparator +
			strings.Join(disclosures, common.CombinedFormatSeparator) +
			common.CombinedFormatSeparator
	}

	return vc, mockVDRRegistry
}

func proveVC(
	t *testing.T,
	credential *verifiable.Credential,
	kt kmskeytypes.KeyType,
	sr verifiable.SignatureRepresentation,
	sf vcsverifiable.Format,
	loader ld.DocumentLoader,
	purpose string,
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

		jws, err := claims.MarshalJWS(jwsAlgo, suite.NewCryptoSigner(customCrypto, kh), didDoc.VerificationMethod[0].ID)
		require.NoError(t, err)

		credential.JWT = jws
	}

	return &vdrmock.MockVDRegistry{
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
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://agent.example.com/"),
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
