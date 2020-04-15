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

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	"github.com/stretchr/testify/require"

	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

func TestCrypto_SignCredential(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(&kmsmock.CloseableKMS{},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{Value: []byte(pubKey)}, nil
			}})

		signedVC, err := c.SignCredential(
			getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test successful sign credential using opts", func(t *testing.T) {
		tests := []struct {
			name              string
			signingOpts       []SigningOpts
			responsePurpose   string
			responseVerMethod string
			err               string
		}{
			{
				name:              "signing with purpose option",
				signingOpts:       []SigningOpts{WithPurpose("sample-purpose")},
				responsePurpose:   "sample-purpose",
				responseVerMethod: "did:test:abc#key1",
			},
			{
				name:              "signing with verification method option",
				signingOpts:       []SigningOpts{WithVerificationMethod("did:sample:xyz#key999")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:sample:xyz#key999",
			},
			{
				name: "signing with verification method, purpose options & representation(proofValue)",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSigningRepresentation("proofValue")},
				responsePurpose:   "sample-purpose",
				responseVerMethod: "did:sample:xyz#key999",
			},
			{
				name: "signing with verification method, purpose options & representation(jws)",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSigningRepresentation("jws")},
				responsePurpose:   "sample-purpose",
				responseVerMethod: "did:sample:xyz#key999",
			},
			{
				name:              "signing with verification method & purpose options",
				signingOpts:       []SigningOpts{},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:test:abc#key1",
			},
			{
				name: "failed with invalid signing representation",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSigningRepresentation("xyz")},
				err: "invalid proof format : xyz",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				pubKey, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				c := New(&kmsmock.CloseableKMS{},
					&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
						return &verifier.PublicKey{Value: []byte(pubKey)}, nil
					}})

				signedVC, err := c.SignCredential(
					getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
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
			})
		}
	})

	t.Run("test success with private key", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(privateKey)

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test signature representation - JWS", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(privateKey)
		p.SignatureRepresentation = verifiable.SignatureJWS

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))

		jwsProof := signedVC.Proofs[0]
		_, ok := jwsProof["jws"]
		require.True(t, ok)
	})

	t.Run("test signature representation - ProofValue", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(privateKey)
		p.SignatureRepresentation = verifiable.SignatureProofValue

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))

		_, ok := signedVC.Proofs[0]["proofValue"]
		require.True(t, ok)
	})

	t.Run("test error from creator", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(&kmsmock.CloseableKMS{},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{Value: []byte(pubKey)}, nil
			}})
		p := getTestProfile()
		p.Creator = "wrongValue"
		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong id [wrongValue] to resolve")
		require.Nil(t, signedVC)
	})

	t.Run("test error from public key fetcher", func(t *testing.T) {
		c := New(&kmsmock.CloseableKMS{},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return nil, fmt.Errorf("error getting public key")
			}})

		signedVC, err := c.SignCredential(
			getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error getting public key")
		require.Nil(t, signedVC)
	})

	t.Run("test error from sign credential", func(t *testing.T) {
		c := New(&kmsmock.CloseableKMS{SignMessageErr: fmt.Errorf("error sign msg")},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{Value: []byte("")}, nil
			}})

		signedVC, err := c.SignCredential(
			getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
		require.Nil(t, signedVC)
	})
}

func getTestProfile() *vcprofile.DataProfile {
	return &vcprofile.DataProfile{
		Name:          "test",
		DID:           "did:test:abc",
		URI:           "https://test.com/credentials",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
	}
}

type mockKeyResolver struct {
	publicKeyFetcherValue verifiable.PublicKeyFetcher
}

func (m *mockKeyResolver) PublicKeyFetcher() verifiable.PublicKeyFetcher {
	return m.publicKeyFetcherValue
}
