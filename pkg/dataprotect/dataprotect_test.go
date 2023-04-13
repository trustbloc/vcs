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
		crypto := NewMockcrypto(gomock.NewController(t))

		chunkSize := 10
		p := dataprotect.NewDataProtector(crypto, chunkSize, cryptoKeyID, 1)
		var data []byte
		for i := 0; i < chunkSize*6; i++ {
			data = append(data, byte(i))
		}

		crypto.EXPECT().Encrypt(gomock.Any(), nil, cryptoKeyID).
			Return([]byte{0x1}, []byte{0x2}, nil).Times(6)

		resp, err := p.Encrypt(context.TODO(), data)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp)
		assert.Len(t, resp, 6)
		for _, r := range resp {
			assert.Equal(t, []byte{0x1}, r.Encrypted)
			assert.Equal(t, []byte{0x2}, r.EncryptedNonce)
		}
	})

	t.Run("encrypt err", func(t *testing.T) {
		crypto := NewMockcrypto(gomock.NewController(t))

		chunkSize := 10
		p := dataprotect.NewDataProtector(crypto, chunkSize, cryptoKeyID, 1)
		var data []byte
		for i := 0; i < chunkSize*6; i++ {
			data = append(data, byte(i))
		}

		crypto.EXPECT().Encrypt(gomock.Any(), nil, cryptoKeyID).
			Return(nil, nil, errors.New("encrypt err")).AnyTimes()

		resp, err := p.Encrypt(context.TODO(), data)
		assert.ErrorContains(t, err, "encrypt err")
		assert.Empty(t, resp)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		crypto := NewMockcrypto(gomock.NewController(t))

		chunkSize := 10
		p := dataprotect.NewDataProtector(crypto, chunkSize, cryptoKeyID, 0)

		crypto.EXPECT().Decrypt(nil, []byte{0x5, 0x7}, []byte{0x1}, cryptoKeyID).
			Return([]byte{0x50, 0x70}, nil)
		crypto.EXPECT().Decrypt(nil, []byte{0x1, 0x2}, []byte{0x2}, cryptoKeyID).
			Return([]byte{0x10, 0x20}, nil)
		crypto.EXPECT().Decrypt(nil, []byte{0x10, 0x3}, []byte{0x3}, cryptoKeyID).
			Return([]byte{0x10, 0x30}, nil)

		resp, err := p.Decrypt(context.TODO(), []*dataprotect.EncryptedChunk{
			{
				Encrypted:      []byte{0x5, 0x7},
				EncryptedNonce: []byte{0x1},
			},
			{
				Encrypted:      []byte{0x1, 0x2},
				EncryptedNonce: []byte{0x2},
			},
			{
				Encrypted:      []byte{0x10, 0x3},
				EncryptedNonce: []byte{0x3},
			},
		})

		assert.NoError(t, err)
		assert.Equal(t, []byte{0x50, 0x70, 0x10, 0x20, 0x10, 0x30}, resp)
	})

	t.Run("err", func(t *testing.T) {
		crypto := NewMockcrypto(gomock.NewController(t))

		chunkSize := 10
		p := dataprotect.NewDataProtector(crypto, chunkSize, cryptoKeyID, 10)
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any(), cryptoKeyID).
			Return(nil, errors.New("decrypt err"))
		resp, err := p.Decrypt(context.TODO(), []*dataprotect.EncryptedChunk{
			{},
			{},
		})

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "decrypt err")
	})
}
