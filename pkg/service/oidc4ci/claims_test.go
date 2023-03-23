/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestEncrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		claims := map[string]interface{}{
			"foo": "bar",
		}
		claimsBytes, _ := json.Marshal(claims)
		encrypted := []byte{0x1, 0x2, 0x3}
		nonce := []byte{0x0, 0x2}

		crypto := NewMockCrypto(gomock.NewController(t))
		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any(), cryptoKeyID).
			DoAndReturn(func(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
				assert.Equal(t, claimsBytes, msg)
				return encrypted, nonce, nil
			})
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			Crypto:      crypto,
			CryptoKeyID: cryptoKeyID,
		})

		data, err := srv.EncryptClaims(map[string]interface{}{
			"foo": "bar",
		})
		assert.NoError(t, err)
		assert.Equal(t, encrypted, data.Encrypted)
		assert.Equal(t, nonce, data.EncryptedNonce)
	})
	t.Run("fail marshal", func(t *testing.T) {
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{})

		data, err := srv.EncryptClaims(map[string]interface{}{
			"foo": make(chan int),
		})
		assert.Nil(t, data)
		assert.ErrorContains(t, err, "json: unsupported type: chan int")
	})

	t.Run("encrypt err", func(t *testing.T) {
		crypto := NewMockCrypto(gomock.NewController(t))
		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, nil, errors.New("can not encrypt"))
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			Crypto: crypto,
		})

		data, err := srv.EncryptClaims(map[string]interface{}{
			"foo": "bar",
		})
		assert.Nil(t, data)
		assert.ErrorContains(t, err, "can not encrypt")
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		claims := map[string]interface{}{
			"foo": "bar",
		}
		claimsBytes, _ := json.Marshal(claims)
		encrypted := []byte{0x1, 0x2, 0x3}
		nonce := []byte{0x0, 0x2}

		crypto := NewMockCrypto(gomock.NewController(t))
		crypto.EXPECT().Decrypt(nil, gomock.Any(), gomock.Any(), cryptoKeyID).
			DoAndReturn(func(cipher, aad, nonce1 []byte, kh interface{}) ([]byte, error) {
				assert.Equal(t, aad, encrypted)
				assert.Equal(t, nonce, nonce1)
				return claimsBytes, nil
			})

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			Crypto:      crypto,
			CryptoKeyID: cryptoKeyID,
		})

		data, err := srv.DecryptClaims(&oidc4ci.ClaimData{
			Encrypted:      encrypted,
			EncryptedNonce: nonce,
		})
		assert.NoError(t, err)
		assert.Equal(t, claims, data)
	})
	t.Run("fail marshal", func(t *testing.T) {
		encrypted := []byte{0x1, 0x2, 0x3}
		nonce := []byte{0x0, 0x2}

		crypto := NewMockCrypto(gomock.NewController(t))
		crypto.EXPECT().Decrypt(nil, gomock.Any(), gomock.Any(), cryptoKeyID).
			Return([]byte{0x1, 0x2}, nil)

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			Crypto:      crypto,
			CryptoKeyID: cryptoKeyID,
		})

		data, err := srv.DecryptClaims(&oidc4ci.ClaimData{
			Encrypted:      encrypted,
			EncryptedNonce: nonce,
		})
		assert.ErrorContains(t, err, "looking for beginning of value")
		assert.Nil(t, data)
	})

	t.Run("encrypt err", func(t *testing.T) {
		encrypted := []byte{0x1, 0x2, 0x3}
		nonce := []byte{0x0, 0x2}

		crypto := NewMockCrypto(gomock.NewController(t))
		crypto.EXPECT().Decrypt(nil, gomock.Any(), gomock.Any(), cryptoKeyID).
			Return(nil, errors.New("can not decrypt"))

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			Crypto:      crypto,
			CryptoKeyID: cryptoKeyID,
		})

		data, err := srv.DecryptClaims(&oidc4ci.ClaimData{
			Encrypted:      encrypted,
			EncryptedNonce: nonce,
		})
		assert.ErrorContains(t, err, "can not decrypt")
		assert.Nil(t, data)
	})
}
