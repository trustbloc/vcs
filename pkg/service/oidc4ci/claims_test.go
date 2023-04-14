/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestEncrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		claims := map[string]interface{}{
			"foo": "bar",
		}
		claimsBytes, _ := json.Marshal(claims)

		chunks := &dataprotect.EncryptedData{
			Encrypted:      []byte{0x1, 0x2, 0x3},
			EncryptedNonce: []byte{0x0, 0x2},
		}
		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, bytes []byte) (*dataprotect.EncryptedData, error) {
				assert.Equal(t, claimsBytes, bytes)
				return chunks, nil
			})
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			DataProtector: crypto,
		})

		data, err := srv.EncryptClaims(context.TODO(), map[string]interface{}{
			"foo": "bar",
		})
		assert.NoError(t, err)
		assert.Equal(t, data.EncryptedData, chunks)
	})
	t.Run("fail marshal", func(t *testing.T) {
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{})

		data, err := srv.EncryptClaims(context.TODO(), map[string]interface{}{
			"foo": make(chan int),
		})
		assert.Nil(t, data)
		assert.ErrorContains(t, err, "json: unsupported type: chan int")
	})

	t.Run("encrypt err", func(t *testing.T) {
		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("can not encrypt"))
		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			DataProtector: crypto,
		})

		data, err := srv.EncryptClaims(context.TODO(), map[string]interface{}{
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

		chunks := &dataprotect.EncryptedData{
			Encrypted:      []byte{0x1, 0x2, 0x3},
			EncryptedNonce: []byte{0x0, 0x2},
		}

		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, chunks2 *dataprotect.EncryptedData) ([]byte, error) {
				assert.Equal(t, chunks, chunks2)

				return claimsBytes, nil
			})

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			DataProtector: crypto,
		})

		data, err := srv.DecryptClaims(context.TODO(), &oidc4ci.ClaimData{
			EncryptedData: chunks,
		})
		assert.NoError(t, err)
		assert.Equal(t, claims, data)
	})
	t.Run("fail marshal", func(t *testing.T) {
		chunks := &dataprotect.EncryptedData{
			Encrypted:      []byte{0x1, 0x2, 0x3},
			EncryptedNonce: []byte{0x0, 0x2},
		}

		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return([]byte{0x1, 0x2}, nil)

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			DataProtector: crypto,
		})

		data, err := srv.DecryptClaims(context.TODO(), &oidc4ci.ClaimData{
			EncryptedData: chunks,
		})
		assert.ErrorContains(t, err, "looking for beginning of value")
		assert.Nil(t, data)
	})

	t.Run("encrypt err", func(t *testing.T) {
		chunks := &dataprotect.EncryptedData{
			Encrypted:      []byte{0x1, 0x2, 0x3},
			EncryptedNonce: []byte{0x0, 0x2},
		}

		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("can not decrypt"))

		srv, _ := oidc4ci.NewService(&oidc4ci.Config{
			DataProtector: crypto,
		})

		data, err := srv.DecryptClaims(context.TODO(), &oidc4ci.ClaimData{
			EncryptedData: chunks,
		})
		assert.ErrorContains(t, err, "can not decrypt")
		assert.Nil(t, data)
	})
}
