/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
)

const (
	key1 = "key1"
)

func TestCommonDID_ResolveDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{},
			VDRI: &vdr.MockVDRegistry{ResolveValue: &ariesdid.Doc{ID: "did:test:123"}}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")), "did:test:123#key1")

		require.NoError(t, err)
		require.Equal(t, "did:test:123#key1", keyID)
		require.Equal(t, "did:test:123", did)
	})

	t.Run("test error - resolve DID", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{},
			VDRI: &vdr.MockVDRegistry{ResolveErr: fmt.Errorf("failed to resolve did")}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")), "did:test:123#key1")

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - import private key", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{ImportPrivateKeyErr: fmt.Errorf("failed to import key")},
			VDRI: &vdr.MockVDRegistry{ResolveValue: &ariesdid.Doc{ID: "did:test:123"}}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")), "did:test:123#key1")

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to import key")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - import private key BBS", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{ImportPrivateKeyErr: fmt.Errorf("failed to import key")},
			VDRI: &vdr.MockVDRegistry{ResolveValue: &ariesdid.Doc{ID: "did:test:123"}}})

		did, keyID, err := c.CreateDID(kms.BLS12381G2, "", "did:test:123", base58.Encode([]byte("key")),
			"did:test:123#key1")

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal private key")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})
}

func TestCommonDID_CreateDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(&Config{VDRI: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *ariesdid.Doc,
				option ...vdrapi.DIDMethodOption) (*ariesdid.DocResolution, error) {
				return &ariesdid.DocResolution{DIDDocument: &ariesdid.Doc{ID: "did:trustbloc:123"}}, nil
			}}})

		c.createKey = func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
			if keyType == kms.ED25519Type {
				_, v, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				return key1, v, nil
			}

			ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

			return key1, ecPubKeyBytes, nil
		}

		tests := []struct {
			keyType       string
			signatureType string
		}{
			{crypto.Ed25519KeyType, crypto.Ed25519Signature2018},
			{crypto.Ed25519KeyType, crypto.JSONWebSignature2020},
			{crypto.P256KeyType, crypto.JSONWebSignature2020},
		}

		for _, test := range tests {
			t.Run(fmt.Sprintf("%s_%s", test.keyType, test.signatureType), func(t *testing.T) {
				did, keyID, err := c.CreateDID(test.keyType, test.signatureType, "", "", "")

				require.NoError(t, err)
				require.Equal(t, "did:trustbloc:123#key1", keyID)
				require.Equal(t, "did:trustbloc:123", did)
			})
		}
	})

	t.Run("test error - create key failed", func(t *testing.T) {
		c := New(&Config{})

		c.createKey = func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
			return "", nil, fmt.Errorf("create key error")
		}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.Ed25519Signature2018, "", "", "")

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create did public key: create key error")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - jwk from public key failed", func(t *testing.T) {
		c := New(&Config{})

		c.createKey = func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
			return key1, nil, nil
		}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.Ed25519Signature2018, "", "", "")

		require.Error(t, err)
		require.Contains(t, err.Error(), "create JWK: unable to read jose JWK")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - create public keys failed", func(t *testing.T) {
		c := New(&Config{})

		c.createKey = func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
			if keyType == kms.ED25519Type {
				_, v, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				return key1, v, nil
			}

			ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

			return key1, ecPubKeyBytes, nil
		}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.Ed25519Signature2018, "", "", "")

		require.Error(t, err)
		require.Contains(t, err.Error(), "no key found to match key type:P256 and signature type:Ed25519Signature2018")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - create did failed", func(t *testing.T) {
		c := New(&Config{VDRI: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *ariesdid.Doc,
				option ...vdrapi.DIDMethodOption) (*ariesdid.DocResolution, error) {
				return nil, fmt.Errorf("failed to create DID")
			}}})

		c.createKey = func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
			if keyType == kms.ED25519Type {
				_, v, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				return key1, v, nil
			}

			ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

			return key1, ecPubKeyBytes, nil
		}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.JSONWebSignature2020, "", "", "")

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create DID")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})
}

func TestCommonDID_CreateKey(t *testing.T) {
	t.Run("test error - export public key failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{ExportPubKeyBytesErr: fmt.Errorf("failed export public key")}})
		_, _, err := c.createKey("ED25519", c.keyManager)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed export public key")
	})
}

func TestCommonDID_ImportKey(t *testing.T) {
	t.Run("test error - key type not supported", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{}})
		err := c.importKey("", "wrongType", []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "import key type not supported wrongType")
	})
}
