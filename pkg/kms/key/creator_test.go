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

	"github.com/stretchr/testify/require"
	ariesmockstorage "github.com/trustbloc/did-go/legacy/mock/storage"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	arieskms "github.com/trustbloc/kms-go/kms"
	mockwrapper "github.com/trustbloc/kms-go/mock/wrapper"
	"github.com/trustbloc/kms-go/secretlock/noop"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"

	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"github.com/trustbloc/kms-go/spi/kms"

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
		keyCreator, get := newKMS(t)

		for kmsType, name := range curves {
			keyID, jwk, err := key.JWKKeyCreator(keyCreator)(kmsType)
			require.NoError(t, err)
			require.NoError(t, get(keyID))
			require.NotNil(t, jwk)
			require.Equal(t, name, jwk.Crv)
		}
	})

	t.Run("error in key creator", func(t *testing.T) {
		expected := errors.New("test")
		kc := &mockwrapper.MockKMSCrypto{
			CreateErr: expected,
		}
		_, _, err := key.JWKKeyCreator(kc)(kms.ED25519Type)
		require.ErrorIs(t, err, expected)
		require.Contains(t, err.Error(), "failed to convert key to JWK")
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
		keyCreator, get := newKMS(t)

		for kmsType, cryptoType := range curves {
			keyID, pubKey, err := key.CryptoKeyCreator(keyCreator)(kmsType)
			require.NoError(t, err)
			require.NoError(t, get(keyID), kmsType)
			require.NotNil(t, pubKey)
			require.IsType(t, cryptoType, pubKey)
		}
	})

	t.Run("error in key creator", func(t *testing.T) {
		expected := errors.New("test")
		kc := &mockwrapper.MockKMSCrypto{
			CreateErr: expected,
		}
		_, _, err := key.CryptoKeyCreator(kc)(kms.ED25519Type)
		require.ErrorIs(t, err, expected)
	})
}

func newKMS(t *testing.T) (api.RawKeyCreator, func(kid string) error) {
	t.Helper()

	p, err := arieskms.NewAriesProviderWrapper(ariesmockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	suite, err := localsuite.NewLocalCryptoSuite("local-lock://custom/primary/key/", p, &noop.NoLock{})
	require.NoError(t, err)

	kc, err := suite.RawKeyCreator()
	require.NoError(t, err)

	signer, err := suite.KMSCryptoMultiSigner()
	require.NoError(t, err)

	return kc, func(kid string) error {
		j := &jwk.JWK{}
		j.KeyID = kid

		msg := []byte("message")
		msgs := [][]byte{msg}

		// some primitives can only Sign, some can only SignMulti
		_, e := signer.Sign(msg, j)
		_, e2 := signer.SignMulti(msgs, j)
		if e != nil && e2 != nil {
			return e
		}

		return nil
	}
}
