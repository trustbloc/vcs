/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/trustbloc/vcs/pkg/kms/signer"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

func TestCrypto_SignCredential(t *testing.T) { //nolint:gocognit
	t.Parallel()

	t.Run("test success", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVC, err := c.SignCredential(
			getTestSigner(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test successful sign credential using opts", func(t *testing.T) {
		prepareTestCreated := func(y, m, d int) *time.Time {
			c := time.Now().AddDate(y, m, d)

			return &c
		}

		tests := []struct {
			name              string
			signingOpts       []SigningOpts
			responsePurpose   string
			responseVerMethod string
			responseDomain    string
			responseChallenge string
			responseTime      *time.Time
			vcSigner          *vc.Signer
			err               string
		}{
			{
				name:              "signing with verification method option",
				signingOpts:       []SigningOpts{WithVerificationMethod("did:trustbloc:abc#key1")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithDomain("example.com")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:trustbloc:abc#key1",
				responseDomain:    "example.com",
			},
			{
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithChallenge("challenge")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:trustbloc:abc#key1",
				responseChallenge: "challenge",
			},
			{
				name:        "signing with verification method option with profile DID",
				signingOpts: []SigningOpts{WithVerificationMethod("did:trustbloc:abc#key1")},
				vcSigner: &vc.Signer{
					DID:           "did:trustbloc:abc",
					SignatureType: "Ed25519Signature2018",
					Creator:       "did:trustbloc:abc#key1",
					KMS:           &mockKMS{},
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name:        "signing with verification method option with profile DID",
				signingOpts: []SigningOpts{WithVerificationMethod("did:trustbloc:abc")},
				err:         "verificationMethod value did:trustbloc:abc should be in did#keyID format",
			},
			{
				name: "signing with verification method, purpose options & representation(proofValue)",
				signingOpts: []SigningOpts{
					WithPurpose(AssertionMethod),
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("proofValue"),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "signing with verification method, purpose, created, type & representation(jws) options",
				signingOpts: []SigningOpts{
					WithPurpose(AssertionMethod),
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("jws"),
					WithCreated(prepareTestCreated(-1, -1, 0)),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
				responseTime:      prepareTestCreated(-1, -1, 0),
			},
			{
				name:              "signing with verification method & purpose options",
				signingOpts:       []SigningOpts{},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "failed with invalid signing representation",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("xyz"),
				},
				err: "invalid proof format : xyz",
			},
			{
				name: "test with JsonWebSignature2020",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("JsonWebSignature2020"),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "test with EcdsaSecp256k1Signature2019",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("EcdsaSecp256k1Signature2019"),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "failed with unsupported signature type",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("123"),
				},
				err: "signature type unsupported 123",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				c := New(
					&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
					testutil.DocumentLoader(t),
				)

				vcSigner := getTestSigner()
				if tc.vcSigner != nil {
					vcSigner = tc.vcSigner
				}

				signedVC, err := c.SignCredential(
					vcSigner, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
					tc.signingOpts...)

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.Equal(t, 1, len(signedVC.Proofs))
				require.Equal(t, tc.responsePurpose, signedVC.Proofs[0]["proofPurpose"])
				require.Equal(t, tc.responseVerMethod, signedVC.Proofs[0]["verificationMethod"])
				require.NotEmpty(t, signedVC.Proofs[0]["created"])

				if signedVC.Proofs[0]["challenge"] != nil {
					require.Equal(t, tc.responseChallenge, signedVC.Proofs[0]["challenge"].(string))
				}

				if signedVC.Proofs[0]["domain"] != nil {
					require.Equal(t, tc.responseDomain, signedVC.Proofs[0]["domain"].(string))
				}

				created, err := time.Parse(time.RFC3339, signedVC.Proofs[0]["created"].(string))
				require.NoError(t, err)

				responseTime := time.Now()

				if tc.responseTime != nil {
					responseTime = *tc.responseTime
				}

				require.Equal(t, responseTime.Year(), created.Year())
				require.Equal(t, responseTime.Month(), created.Month())
			})
		}
	})

	t.Run("test error from creator", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)
		p := getTestSigner()
		p.Creator = "wrongValue"
		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "verificationMethod value wrongValue should be in did#keyID format")
		require.Nil(t, signedVC)
	})

	t.Run("test error from sign credential", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)
		signedVC, err := c.SignCredential(
			getTestSignerWithCrypto(
				&cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}),
			&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
		require.Nil(t, signedVC)
	})

	t.Run("sign vc - invalid proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestSigner()

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "proof purpose invalid not supported")
		require.Nil(t, signedVC)
	})

	t.Run("sign vc - capability invocation proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestSigner()

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose(CapabilityInvocation))
		require.NoError(t, err)
		require.NotNil(t, signedVC)
	})

	t.Run("sign vc - capability delegation proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestSigner()

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose(CapabilityInvocation))
		require.NoError(t, err)
		require.NotNil(t, signedVC)
	})
}

func TestCrypto_SignCredentialBBS(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVC, err := c.SignCredential(
			&vc.Signer{
				DID:           "did:trustbloc:abc",
				SignatureType: "BbsBlsSignature2020",
				Creator:       "did:trustbloc:abc#key1",
				KMS:           &mockKMS{},
			}, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})
}

func TestSignPresentation(t *testing.T) {
	t.Run("sign presentation - success", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
		)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVP.Proofs))
	})

	t.Run("sign presentation - signature type opts", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType(Ed25519Signature2020),
		)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVP.Proofs))
	})

	t.Run("sign presentation - fail", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType("invalid"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type unsupported invalid")
		require.Nil(t, signedVP)
	})

	t.Run("sign presentation - unresolved did", func(t *testing.T) {
		c := New(
			&vdrmock.MockVDRegistry{ResolveValue: nil},
			nil,
		)

		signedVP, err := c.SignPresentation(getTestSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType(Ed25519Signature2018),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DID does not exist")
		require.Nil(t, signedVP)
	})
}

func getTestSigner() *vc.Signer {
	return &vc.Signer{
		DID:           "did:trustbloc:abc",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:trustbloc:abc#key1",
		KMS:           &mockKMS{},
	}
}

func getTestSignerWithCrypto(crypto ariescrypto.Crypto) *vc.Signer {
	return &vc.Signer{
		DID:           "did:trustbloc:abc",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:trustbloc:abc#key1",
		KMS:           &mockKMS{crypto: crypto},
	}
}

type mockKMS struct {
	crypto ariescrypto.Crypto
}

func (m *mockKMS) NewVCSigner(creator string, signatureType vc.SignatureType) (vc.SignerAlgorithm, error) {
	if m.crypto == nil {
		m.crypto = &cryptomock.Crypto{}
	}

	return signer.NewKMSSigner(&mockkms.KeyManager{}, m.crypto, creator, signatureType)
}

// nolint: unparam
func createDIDDoc(didID string) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := didID + "#key1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}
