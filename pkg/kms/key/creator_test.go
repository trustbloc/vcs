/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/trustbloc/vcs/pkg/kms/key"
)

func TestJWKKeyCreator(t *testing.T) {
	t.Run("creates keys", func(t *testing.T) {
		curves := map[kms.KeyType]string{
			kms.ED25519Type:            "Ed25519",
			kms.ECDSAP256TypeIEEEP1363: "P-256",
			kms.ECDSAP384TypeIEEEP1363: "P-384",
			kms.ECDSAP521TypeIEEEP1363: "P-521",
			kms.BLS12381G2Type:         "BLS12381_G2",
		}
		k := newKMS(t)

		for kmsType, name := range curves {
			keyID, jwk, err := key.JWKKeyCreator(kmsType)(k)
			require.NoError(t, err)
			_, err = k.Get(keyID)
			require.NoError(t, err)
			require.NotNil(t, jwk)
			require.Equal(t, name, jwk.Crv)
		}
	})

	t.Run("error if kms cannot create key", func(t *testing.T) {
		expected := errors.New("test")
		k := &mockkms.KeyManager{
			CrAndExportPubKeyErr: expected,
		}
		_, _, err := key.JWKKeyCreator(kms.ED25519Type)(k)
		require.ErrorIs(t, err, expected)
	})

	t.Run("error building JWK", func(t *testing.T) {
		k := &mockkms.KeyManager{}
		_, _, err := key.JWKKeyCreator(kms.ECDSAP256TypeIEEEP1363)(k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to convert key to JWK")
	})
	t.Run("error parse BLS12381_G2", func(t *testing.T) {
		k := &mockkms.KeyManager{}
		_, _, err := key.JWKKeyCreator(kms.BLS12381G2Type)(k)
		require.Error(t, err)
	})
	t.Run("error parse p256k1", func(t *testing.T) {
		_, _, err := key.JWKKeyCreator(kms.ECDSASecp256k1DER)(&kmsMock{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "asn1: syntax error")
	})
}

func TestCryptoKeyCreator(t *testing.T) {
	t.Run("creates keys", func(t *testing.T) {
		curves := map[kms.KeyType]interface{}{
			kms.ED25519Type:            ed25519.PublicKey{},
			kms.ECDSAP256TypeIEEEP1363: &ecdsa.PublicKey{},
			kms.ECDSAP256TypeDER:       &ecdsa.PublicKey{},
			kms.ECDSAP384TypeIEEEP1363: &ecdsa.PublicKey{},
			kms.ECDSAP384TypeDER:       &ecdsa.PublicKey{},
			kms.ECDSAP521TypeIEEEP1363: &ecdsa.PublicKey{},
			kms.ECDSAP521TypeDER:       &ecdsa.PublicKey{},
			kms.BLS12381G2Type:         &bbs12381g2pub.PublicKey{},
		}
		k := newKMS(t)

		for kmsType, cryptoType := range curves {
			keyID, pubKey, err := key.CryptoKeyCreator(kmsType)(k)
			require.NoError(t, err)
			_, err = k.Get(keyID)
			require.NoError(t, err)
			require.NotNil(t, pubKey)
			require.IsType(t, cryptoType, pubKey)
		}
	})

	t.Run("error if kms cannot create the key", func(t *testing.T) {
		expected := errors.New("test")
		k := &mockkms.KeyManager{
			CrAndExportPubKeyErr: expected,
		}
		_, _, err := key.CryptoKeyCreator(kms.ED25519Type)(k)
		require.ErrorIs(t, err, expected)
	})

	t.Run("error on invalid key DER format", func(t *testing.T) {
		k := &mockkms.KeyManager{}
		_, _, err := key.CryptoKeyCreator(kms.ECDSAP256TypeDER)(k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse ecdsa key in DER format")
	})

	t.Run("error on unsupported key type", func(t *testing.T) {
		_, _, err := key.CryptoKeyCreator(kms.NISTP256ECDHKW)(newKMS(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key type")
	})
	t.Run("error parse p256k1", func(t *testing.T) {
		_, _, err := key.CryptoKeyCreator(kms.ECDSASecp256k1DER)(&kmsMock{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "asn1: syntax error")
	})

	t.Run("error parse BLS12381G2", func(t *testing.T) {
		_, _, err := key.CryptoKeyCreator(kms.BLS12381G2Type)(&kmsMock{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid size of public key")
	})
}

func newKMS(t *testing.T) kms.KeyManager {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(mem.NewProvider(), &noop.NoLock{})
	require.NoError(t, err)

	keyManager, err := localkms.New("local-lock://custom/master/key/", p)
	require.NoError(t, err)

	return keyManager
}

type kmsMock struct {
}

func (m *kmsMock) CreateAndExportPubKeyBytes(_ kms.KeyType, _ ...kms.KeyOpts) (string, []byte, error) {
	return "k1", []byte{}, nil
}
