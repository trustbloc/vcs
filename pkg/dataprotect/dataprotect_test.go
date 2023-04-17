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
		compress := NewMockdataCompressor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt, compress)

		data := []byte{0x1, 0x2, 0x66, 0x32}
		dataCompressed := []byte{0x5, 0x6, 0x7}
		encryptedData := []byte{0x99, 0x55, 0x66}
		key := []byte{0x12}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		compress.EXPECT().Compress(data).Return(dataCompressed, nil)
		encrypt.EXPECT().Encrypt(dataCompressed).
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
		compress := NewMockdataCompressor(gomock.NewController(t))

		compress.EXPECT().Compress(gomock.Any()).Return(nil, nil)
		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt, compress)
		encrypt.EXPECT().Encrypt(gomock.Any()).
			Return(nil, nil, errors.New("data encrypt err"))

		resp, err := p.Encrypt(context.TODO(), []byte{0x0})
		assert.ErrorContains(t, err, "data encrypt err")
		assert.Empty(t, resp)
	})

	t.Run("encrypt err", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		encrypt := NewMockdataEncryptor(gomock.NewController(t))
		compress := NewMockdataCompressor(gomock.NewController(t))
		compress.EXPECT().Compress(gomock.Any()).Return(nil, nil)

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt, compress)
		encrypt.EXPECT().Encrypt(gomock.Any()).
			Return(nil, nil, nil)
		keyProtector.EXPECT().Encrypt(gomock.Any(), nil, cryptoKeyID).
			Return(nil, nil, errors.New("encrypt err"))

		resp, err := p.Encrypt(context.TODO(), []byte{0x0})
		assert.ErrorContains(t, err, "encrypt err")
		assert.Empty(t, resp)
	})

	t.Run("compress err", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		encrypt := NewMockdataEncryptor(gomock.NewController(t))
		compress := NewMockdataCompressor(gomock.NewController(t))
		compress.EXPECT().Compress(gomock.Any()).Return(nil, errors.New("can not compress"))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, encrypt, compress)

		resp, err := p.Encrypt(context.TODO(), []byte{0x0})
		assert.ErrorContains(t, err, "can not compress")
		assert.Empty(t, resp)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))
		compress := NewMockdataCompressor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector, compress)

		data := []byte{0x1, 0x2, 0x66, 0x32}
		dataDecompressed := []byte{0x1, 0x1, 0x2}
		encryptedData := []byte{0x99, 0x55, 0x66}
		key := []byte{0x12}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		compress.EXPECT().Decompress(data).Return(dataDecompressed, nil)
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

		assert.Equal(t, dataDecompressed, dec)
	})

	t.Run("fail decrypt key", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))
		compress := NewMockdataCompressor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector, compress)

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
		compress := NewMockdataCompressor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector, compress)

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

	t.Run("fail decompress", func(t *testing.T) {
		keyProtector := NewMockcrypto(gomock.NewController(t))
		dataProtector := NewMockdataEncryptor(gomock.NewController(t))
		compress := NewMockdataCompressor(gomock.NewController(t))

		p := dataprotect.NewDataProtector(keyProtector, cryptoKeyID, dataProtector, compress)

		data := []byte{0x1, 0x2, 0x66, 0x32}
		encryptedData := []byte{0x99, 0x55, 0x66}
		key := []byte{0x12}
		encryptedKey := []byte{0x88, 0x77}
		nonce := []byte{0x5}

		compress.EXPECT().Decompress(data).Return(nil, errors.New("can not decompress"))
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
		assert.Nil(t, dec)
		assert.ErrorContains(t, err, "can not decompress")
	})
}
