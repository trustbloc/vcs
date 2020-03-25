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
