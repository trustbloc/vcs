/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	_ "embed"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	mockwrapper "github.com/trustbloc/kms-go/mock/wrapper"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vcs/internal/mock/vcskms"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

func TestCrypto_SignCredentialLDPDataIntegrity(t *testing.T) { //nolint:gocognit
	suite := createCryptoSuite(t)

	keyCreator, err := suite.KeyCreator()
	require.NoError(t, err)

	key, err := keyCreator.Create(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	const signingDID = "did:foo:bar"

	const vmID = "#key1"

	verificationMethod, err := did.NewVerificationMethodFromJWK(vmID, "JsonWebKey2020", signingDID, key)
	require.NoError(t, err)

	c := New(
		&vdrmock.VDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return makeMockDIDResolution(signingDID, verificationMethod, did.AssertionMethod), nil
			}},
		testutil.DocumentLoader(t),
	)

	testSigner := getTestLDPDataIntegritySigner()

	unsignedVc, err := verifiable.CreateCredential(verifiable.CredentialContents{
		ID:      "http://example.edu/credentials/1872",
		Context: []string{verifiable.V1ContextURI},
		Types:   []string{verifiable.VCType},
		Subject: []verifiable.Subject{{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
			CustomFields: map[string]interface{}{
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name":   "Jayden Doe",
				"degree": map[string]interface{}{
					"type":   "BachelorDegree",
					"degree": "MIT",
				},
			},
		}},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: &verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
	}, map[string]interface{}{
		"first_name": "First name",
		"last_name":  "Last name",
		"info":       "Info",
	})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		signedVC, err := c.signCredentialLDPDataIntegrity(testSigner, unsignedVc)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs()))

		require.Equal(t, "DataIntegrityProof", signedVC.Proofs()[0]["type"])
		require.Equal(t, "ecdsa-2019", signedVC.Proofs()[0]["cryptosuite"])
		require.Equal(t, "#key1", signedVC.Proofs()[0]["verificationMethod"])
		require.Equal(t, "assertionMethod", signedVC.Proofs()[0]["proofPurpose"])
		require.Empty(t, signedVC.Proofs()[0]["challenge"])
		require.Empty(t, signedVC.Proofs()[0]["domain"])
		require.NotEmpty(t, signedVC.Proofs()[0]["proofValue"])
	})

	t.Run("Success with options", func(t *testing.T) {
		testCrypto := New(
			&vdrmock.VDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return makeMockDIDResolution(signingDID, verificationMethod, did.AssertionMethod), nil
				}},
			testutil.DocumentLoader(t),
		)
		now := time.Now()

		signedVC, err := testCrypto.signCredentialLDPDataIntegrity(testSigner, unsignedVc,
			WithDomain("example.com"),
			WithChallenge("challenge"),
			WithCreated(&now),
			WithPurpose(AssertionMethod),
			WithSignatureType("JsonWebSignature2020"),
		)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs()))

		require.Equal(t, "DataIntegrityProof", signedVC.Proofs()[0]["type"])
		require.Equal(t, "ecdsa-2019", signedVC.Proofs()[0]["cryptosuite"])
		require.Equal(t, "#key1", signedVC.Proofs()[0]["verificationMethod"])
		require.Equal(t, "assertionMethod", signedVC.Proofs()[0]["proofPurpose"])
		require.Equal(t, "challenge", signedVC.Proofs()[0]["challenge"])
		require.Equal(t, "example.com", signedVC.Proofs()[0]["domain"])
		require.NotEmpty(t, signedVC.Proofs()[0]["proofValue"])
	})

	t.Run("Error invalid suite", func(t *testing.T) {
		testCredentials, err := verifiable.CreateCredential(
			verifiable.CredentialContents{ID: "http://example.edu/credentials/1872"}, nil)
		require.NoError(t, err)

		ariesSigner := getTestLDPDataIntegritySigner()
		ariesSigner.DataIntegrityProof.SuiteType = "undefined"

		signedVC, err := c.signCredentialLDPDataIntegrity(ariesSigner, testCredentials)
		require.Nil(t, signedVC)
		require.ErrorContains(t, err, "get data integrity signer initializer: data integrity suite \"undefined\" unsupported")
	})

	t.Run("Error get signer", func(t *testing.T) {
		ariesSigner := getTestLDPDataIntegritySigner()

		ariesSigner.KMS = &vcskms.MockKMS{
			Signer: &mockwrapper.MockKMSCrypto{FixedKeyCryptoErr: errors.New("some error")},
		}

		signedVC, err := c.signCredentialLDPDataIntegrity(ariesSigner, unsignedVc)
		require.Nil(t, signedVC)
		require.Error(t, err)
		require.ErrorContains(t, err, "some error")
	})

	t.Run("Error add proof", func(t *testing.T) {
		testCredentials, err := verifiable.CreateCredential(
			verifiable.CredentialContents{ID: "http://example.edu/credentials/1872"}, nil)
		require.NoError(t, err)

		testCrypto := New(
			&vdrmock.VDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return nil, errors.New("some error")
				}},
			testutil.DocumentLoader(t),
		)

		signedVC, err := testCrypto.signCredentialLDPDataIntegrity(testSigner, testCredentials)
		require.Nil(t, signedVC)
		require.ErrorContains(t, err, "add data integrity proof: failed to resolve verification method")
	})
}

func makeMockDIDResolution(id string, vm *did.VerificationMethod, vr did.VerificationRelationship) *did.DocResolution {
	ver := []did.Verification{{
		VerificationMethod: *vm,
		Relationship:       vr,
	}}

	doc := &did.Doc{
		ID: id,
	}

	switch vr { //nolint:exhaustive
	case did.VerificationRelationshipGeneral:
		doc.VerificationMethod = []did.VerificationMethod{*vm}
	case did.Authentication:
		doc.Authentication = ver
	case did.AssertionMethod:
		doc.AssertionMethod = ver
	}

	return &did.DocResolution{
		DIDDocument: doc,
	}
}
