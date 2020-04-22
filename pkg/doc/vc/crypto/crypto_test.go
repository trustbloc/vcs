/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	gojose "github.com/square/go-jose/v3"
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

	t.Run("test success with jwk", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(&kmsmock.CloseableKMS{},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{Key: pubKey},
					Kty:        "OKP",
					Crv:        "Ed25519",
				}}, nil
			}})

		signedVC, err := c.SignCredential(
			getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test key not supported", func(t *testing.T) {
		c := New(&kmsmock.CloseableKMS{},
			&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{},
					Kty:        "OKP",
					Crv:        "Ed25519",
				}}, nil
			}})

		signedVC, err := c.SignCredential(
			getTestProfile(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not ed25519.PublicKey")
		require.Nil(t, signedVC)
	})

	t.Run("test successful sign credential using opts", func(t *testing.T) {
		_, priKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

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
			profile           *vcprofile.DataProfile
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
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithDomain("example.com")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:test:abc#key1",
				responseDomain:    "example.com",
			},
			{
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithChallenge("challenge")},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:test:abc#key1",
				responseChallenge: "challenge",
			},
			{
				name:        "signing with verification method option with profile DID",
				signingOpts: []SigningOpts{WithVerificationMethod("did:test:abc#key-1")},
				profile: &vcprofile.DataProfile{
					Name:          "test",
					DID:           "did:test:abc",
					URI:           "https://test.com/credentials",
					SignatureType: "Ed25519Signature2018",
					Creator:       "did:test:abc#key1",
					DIDPrivateKey: base58.Encode(priKey),
					DIDKeyType:    Ed25519KeyType,
				},
				responsePurpose:   "assertionMethod",
				responseVerMethod: "did:test:abc#key-1",
			},
			{
				name:        "signing with verification method option with profile DID",
				signingOpts: []SigningOpts{WithVerificationMethod("did:test:abc")},
				err:         "wrong id [did:test:abc] to resolve",
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
				name: "signing with verification method, purpose, created, type & representation(jws) options",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSigningRepresentation("jws"),
					WithCreated(prepareTestCreated(-1, -1, 0))},
				responsePurpose:   "sample-purpose",
				responseVerMethod: "did:sample:xyz#key999",
				responseTime:      prepareTestCreated(-1, -1, 0),
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
			{
				name: "test with JsonWebSignature2020",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSignatureType("JsonWebSignature2020")},
				responsePurpose:   "sample-purpose",
				responseVerMethod: "did:sample:xyz#key999",
			},
			{
				name: "failed with unsupported signature type",
				signingOpts: []SigningOpts{WithPurpose("sample-purpose"),
					WithVerificationMethod("did:sample:xyz#key999"),
					WithSignatureType("123")},
				err: "signature type unsupported 123",
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

				profile := getTestProfile()
				if tc.profile != nil {
					profile = tc.profile
				}

				signedVC, err := c.SignCredential(
					profile, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
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

	t.Run("test success - ed25519 private key", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(privateKey)
		p.DIDKeyType = Ed25519KeyType

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test success - P-256 private key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encodedPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(encodedPrivateKey)
		p.DIDKeyType = P256KeyType

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test P-256 private key parse failure", func(t *testing.T) {
		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = "invalid-private-key"
		p.DIDKeyType = P256KeyType

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse EC private key")
		require.Nil(t, signedVC)
	})

	t.Run("test signing failure - invalid key type", func(t *testing.T) {
		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = "privateKey"
		p.DIDKeyType = "invalid-key-type"

		signedVC, err := c.SignCredential(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type")
		require.Nil(t, signedVC)
	})

	t.Run("test signature representation - JWS", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c := New(nil, nil)

		p := getTestProfile()
		p.DIDPrivateKey = base58.Encode(privateKey)
		p.DIDKeyType = Ed25519KeyType
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
		p.DIDKeyType = Ed25519KeyType

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
