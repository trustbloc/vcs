/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

const (
	cryptoKeyID = "1235432523"
)

func TestNewDataProtectorEncrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		encrypt := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt)

		data := []byte{0x1, 0x2, 0x66, 0x32}
		encryptedData := []byte{0x99, 0x55, 0x66}
		key := []byte{0x12}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		encrypt.EXPECT().Encrypt(data).
			Return(encryptedData, key, nil)
		keyProtector.EXPECT().
			Encrypt(key, nil, cryptoKeyID).
			Return(encryptedKey, nonce, nil)

		enc, err := p.Encrypt(context.TODO(), data)
		assert.NoError(t, err)

		assert.Equal(t, encryptedData, enc.Encrypted)
		assert.Equal(t, nonce, enc.EncryptedNonce)
		assert.Equal(t, encryptedKey, enc.EncryptedKey)
	})

	t.Run("data encrypt err", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		encrypt := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt)
		encrypt.EXPECT().Encrypt(gomock.Any()).
			Return(nil, nil, errors.New("data encrypt err"))

		resp, err := p.Encrypt(context.TODO(), []byte{0x0})
		assert.ErrorContains(t, err, "data encrypt err")
		assert.Empty(t, resp)
	})

	t.Run("encrypt err", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		encrypt := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt)
		encrypt.EXPECT().Encrypt(gomock.Any()).
			Return(nil, nil, nil)
		keyProtector.EXPECT().Encrypt(gomock.Any(), nil, cryptoKeyID).
			Return(nil, nil, errors.New("encrypt err"))

		resp, err := p.Encrypt(context.TODO(), []byte{0x0})
		assert.ErrorContains(t, err, "encrypt err")
		assert.Empty(t, resp)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector)

		data := []byte{0x1, 0x2, 0x66, 0x32}
		encryptedData := []byte{0x99, 0x55, 0x66}
		key := []byte{0x12}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		dataProtector.EXPECT().Decrypt(encryptedData, key).
			Return(data, nil)

		keyProtector.EXPECT().
			Decrypt(nil, encryptedKey, nonce, cryptoKeyID).
			Return(key, nil)

		dec, err := p.Decrypt(context.TODO(), &dataprotect.EncryptedData{
			Encrypted:      encryptedData,
			EncryptedKey:   encryptedKey,
			EncryptedNonce: nonce,
		})
		assert.NoError(t, err)

		assert.Equal(t, data, dec)
	})

	t.Run("fail decrypt key", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector)

		encryptedData := []byte{0x99, 0x55, 0x66}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		keyProtector.EXPECT().
			Decrypt(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("can not decrypt key"))

		dec, err := p.Decrypt(context.TODO(), &dataprotect.EncryptedData{
			Encrypted:      encryptedData,
			EncryptedKey:   encryptedKey,
			EncryptedNonce: nonce,
		})
		assert.Error(t, err, "can not decrypt key")

		assert.Nil(t, dec)
	})

	t.Run("fail decrypt key", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector)

		encryptedData := []byte{0x99, 0x55, 0x66}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		dataProtector.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("can not decrypt data"))

		keyProtector.EXPECT().
			Decrypt(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, nil)

		dec, err := p.Decrypt(context.TODO(), &dataprotect.EncryptedData{
			Encrypted:      encryptedData,
			EncryptedKey:   encryptedKey,
			EncryptedNonce: nonce,
		})
		assert.Error(t, err, "can not decrypt data")

		assert.Nil(t, dec)
	})
}
