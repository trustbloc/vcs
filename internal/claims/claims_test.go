/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package claims_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/internal/claims"
	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestEncryptClaims(t *testing.T) {
	protector := NewMockdataProtector(gomock.NewController(t))
	ctx := context.Background()
	data := map[string]interface{}{"key": "value"}

	bytesData, e := json.Marshal(data)
	require.NoError(t, e)

	tests := []struct {
		name  string
		setup func(t *testing.T)
		check func(t *testing.T, encrypted *issuecredential.ClaimData, err error)
	}{
		{
			name: "Success",
			setup: func(t *testing.T) {
				protector.EXPECT().
					Encrypt(ctx, bytesData).Return(&dataprotect.EncryptedData{
					Encrypted: bytesData,
				}, nil)
			},
			check: func(t *testing.T, encrypted *issuecredential.ClaimData, err error) {
				assert.NoError(t, err)

				assert.Equal(t, &issuecredential.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted: bytesData,
					},
				}, encrypted)
			},
		},
		{
			name: "failure: protector error",
			setup: func(t *testing.T) {
				protector.EXPECT().
					Encrypt(ctx, bytesData).Return(nil, errors.New("protector error"))
			},
			check: func(t *testing.T, encrypted *issuecredential.ClaimData, err error) {
				assert.ErrorContains(t, err, "encrypt claims: protector error")
				assert.Nil(t, encrypted)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			got, err := claims.EncryptClaims(ctx, data, protector)

			tt.check(t, got, err)
		})
	}
}

func TestDecryptClaims(t *testing.T) {
	protector := NewMockdataProtector(gomock.NewController(t))
	ctx := context.Background()
	decryptedData := map[string]interface{}{"key": "value"}

	decryptedDataBytes, e := json.Marshal(decryptedData)
	require.NoError(t, e)

	encryptedData := &issuecredential.ClaimData{
		EncryptedData: &dataprotect.EncryptedData{
			Encrypted: decryptedDataBytes,
		},
	}

	tests := []struct {
		name  string
		setup func(t *testing.T)
		check func(t *testing.T, decrypted map[string]interface{}, err error)
	}{
		{
			name: "Success",
			setup: func(t *testing.T) {
				protector.EXPECT().
					Decrypt(ctx, encryptedData.EncryptedData).Return(decryptedDataBytes, nil)
			},
			check: func(t *testing.T, decrypted map[string]interface{}, err error) {
				assert.NoError(t, err)

				assert.Equal(t, decryptedData, decrypted)
			},
		},
		{
			name: "failure: protector error",
			setup: func(t *testing.T) {
				protector.EXPECT().
					Decrypt(ctx, encryptedData.EncryptedData).Return(nil, errors.New("protector error"))
			},
			check: func(t *testing.T, decrypted map[string]interface{}, err error) {
				assert.ErrorContains(t, err, "decrypt claims: protector error")
				assert.Nil(t, decrypted)
			},
		},
		{
			name: "failure: json decode error",
			setup: func(t *testing.T) {
				protector.EXPECT().
					Decrypt(ctx, encryptedData.EncryptedData).Return([]byte(`[]`), nil)
			},
			check: func(t *testing.T, decrypted map[string]interface{}, err error) {
				assert.ErrorContains(t, err, "unmarshal")
				assert.Nil(t, decrypted)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			got, err := claims.DecryptClaims(ctx, encryptedData, protector)

			tt.check(t, got, err)
		})
	}
}
