/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

func TestTxManager_CreateTx(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), profileID, profileVersion, int32(20), []string{customScope}).Return(
			oidc4vp.TxID("txID"),
			&oidc4vp.Transaction{
				ID:             "txID",
				ProfileID:      profileID,
				ProfileVersion: profileVersion,
				CustomScopes:   []string{customScope},
			},
			nil,
		)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().SetIfNotExist(gomock.Any(), int32(10), oidc4vp.TxID("txID")).
			Times(1).Return(true, nil)

		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		tx, nonce, err := manager.CreateTx(
			&presexch.PresentationDefinition{}, profileID, profileVersion, int32(20), int32(10), []string{customScope})

		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.NotNil(t, tx)
		require.Equal(t, profileID, tx.ProfileID)
		require.Equal(t, profileVersion, tx.ProfileVersion)
		require.Equal(t, []string{customScope}, tx.CustomScopes)
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), profileID, profileVersion, int32(20), []string{customScope}).
			Return(oidc4vp.TxID(""), nil, errors.New("test error"))

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, _, err := manager.CreateTx(
			&presexch.PresentationDefinition{}, profileID, profileVersion, int32(20), int32(10), []string{customScope})

		require.Contains(t, err.Error(), "test error")
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), profileID, profileVersion, int32(20), nil).Return(oidc4vp.TxID("txID"), nil, nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().SetIfNotExist(gomock.Any(), int32(10), oidc4vp.TxID("txID")).
			Times(1).Return(false, errors.New("test error"))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, _, err := manager.CreateTx(
			&presexch.PresentationDefinition{}, profileID, profileVersion, int32(20), int32(10), nil)

		require.Contains(t, err.Error(), "test error")
	})
}

func TestTxManager_GetByOneTimeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(&oidc4vp.Transaction{ID: "txID", ProfileID: "org_id"}, nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete("nonce").Times(1).Return(oidc4vp.TxID("txID"), true, nil)
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		tx, exists, err := manager.GetByOneTimeToken("nonce")

		require.NoError(t, err)
		require.True(t, exists)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
	})

	t.Run("Fail GetAndDelete", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete(gomock.Any()).Times(1).Return(oidc4vp.TxID(""), true,
			errors.New("test error 123"))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, exists, err := manager.GetByOneTimeToken("nonce")

		require.False(t, exists)
		require.Contains(t, err.Error(), "test error 123")
	})

	t.Run("Fail Get", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, errors.New("test error 333"))

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete("nonce").Times(1).Return(oidc4vp.TxID("txID"), true, nil)
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, exists, err := manager.GetByOneTimeToken("nonce")

		require.False(t, exists)
		require.Contains(t, err.Error(), "test error 333")
	})
}

func TestTxManager_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(&oidc4vp.Transaction{ID: "txID", ProfileID: "org_id"}, nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		tx, err := manager.Get("txID")

		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
		require.Nil(t, tx.ReceivedClaims)
		require.Empty(t, tx.ReceivedClaimsID)
	})

	t.Run("Success - with claims ID", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(
			&oidc4vp.Transaction{
				ID:               "txID",
				ProfileID:        "org_id",
				ReceivedClaimsID: "claims_id"},
			nil)

		encryptedClaims := []byte{0x0, 0x1, 0x2}
		nonce := []byte{0x3, 0x4}

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		chunks := &dataprotect.EncryptedData{
			Encrypted:      encryptedClaims,
			EncryptedNonce: nonce,
		}
		claimsStore.EXPECT().Get(gomock.Any()).Return(&oidc4vp.ClaimData{
			EncryptedData: chunks,
		}, nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		crypto.EXPECT().Decrypt(gomock.Any(), chunks).
			DoAndReturn(func(ctx context.Context, chunks1 *dataprotect.EncryptedData) ([]byte, error) {
				assert.Equal(t, chunks, chunks1)

				vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)
				vcSD, err := verifiable.ParseCredential([]byte(sampleVCJWT),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)
				ld, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)

				rs := &oidc4vp.ReceivedClaims{
					Credentials: []*verifiable.Credential{
						vc,
						vcSD,
						ld,
					},
					CustomScopeClaims: nil,
				}
				raw, err := manager.ClaimsToClaimsRaw(rs)
				assert.NoError(t, err)

				b, err := json.Marshal(raw)
				assert.NoError(t, err)

				return b, nil
			})

		tx, err := manager.Get("txID")

		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
		require.Equal(t, tx.ReceivedClaimsID, "claims_id")
		require.NotNil(t, tx.ReceivedClaims)
		require.Nil(t, tx.ReceivedClaims.CustomScopeClaims)
	})

	t.Run("Success - with claims ID and custom claims", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(
			&oidc4vp.Transaction{
				ID:               "txID",
				ProfileID:        "org_id",
				ReceivedClaimsID: "claims_id"},
			nil)

		encryptedClaims := []byte{0x0, 0x1, 0x2}
		nonce := []byte{0x3, 0x4}

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		chunks := &dataprotect.EncryptedData{
			Encrypted:      encryptedClaims,
			EncryptedNonce: nonce,
		}
		claimsStore.EXPECT().Get(gomock.Any()).Return(&oidc4vp.ClaimData{
			EncryptedData: chunks,
		}, nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		crypto.EXPECT().Decrypt(gomock.Any(), chunks).
			DoAndReturn(func(ctx context.Context, chunks1 *dataprotect.EncryptedData) ([]byte, error) {
				assert.Equal(t, chunks, chunks1)

				vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)
				vcSD, err := verifiable.ParseCredential([]byte(sampleVCJWT),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)
				ld, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
					verifiable.WithDisabledProofCheck())
				assert.NoError(t, err)

				rs := &oidc4vp.ReceivedClaims{
					Credentials: []*verifiable.Credential{
						vc,
						vcSD,
						ld,
					},
					CustomScopeClaims: map[string]oidc4vp.Claims{
						customScope: {
							"key1": "value1",
							"key2": float64(2),
							"key3": map[string]interface{}{"key4": "value4"},
						},
					},
				}
				raw, err := manager.ClaimsToClaimsRaw(rs)
				assert.NoError(t, err)

				b, err := json.Marshal(raw)
				assert.NoError(t, err)

				return b, nil
			})

		tx, err := manager.Get("txID")

		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
		require.Equal(t, tx.ReceivedClaimsID, "claims_id")
		require.NotNil(t, tx.ReceivedClaims)
		require.Equal(t, map[string]oidc4vp.Claims{
			customScope: {
				"key1": "value1",
				"key2": float64(2),
				"key3": map[string]interface{}{"key4": "value4"},
			},
		}, tx.ReceivedClaims.CustomScopeClaims)
	})

	t.Run("Success - claims not found", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(
			&oidc4vp.Transaction{
				ID:               "txID",
				ProfileID:        "org_id",
				ReceivedClaimsID: "claims_id"},
			nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		claimsStore.EXPECT().Get(gomock.Any()).Return(nil, oidc4vp.ErrDataNotFound)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		tx, err := manager.Get("txID")

		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
		require.Equal(t, tx.ReceivedClaimsID, "claims_id")
		require.Nil(t, tx.ReceivedClaims)
	})

	t.Run("Error - claims store error", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(
			&oidc4vp.Transaction{
				ID:               "txID",
				ProfileID:        "org_id",
				ReceivedClaimsID: "claims_id"},
			nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		claimsStore.EXPECT().Get(gomock.Any()).Return(nil, fmt.Errorf("store error"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		tx, err := manager.Get("txID")

		require.Error(t, err)
		require.Nil(t, tx)
		require.Contains(t, err.Error(), "find received claims: store error")
	})

	t.Run("Fail Get", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, errors.New("test error 333"))

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, err := manager.Get("txID")

		require.Contains(t, err.Error(), "test error 333")
	})

	t.Run("Fail Get 2", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, oidc4vp.ErrDataNotFound)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		_, err := manager.Get("txID")

		require.Contains(t, err.Error(), "data not found")
	})
}

func TestTxManagerStoreReceivedClaims(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Update(gomock.Any(), int32(20)).Return(nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		chunks := &dataprotect.EncryptedData{
			Encrypted:      []byte{0x0, 0x1, 0x2},
			EncryptedNonce: []byte{0x3, 0x4},
		}

		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, bytes []byte) (*dataprotect.EncryptedData, error) {
				assert.NotEmpty(t, bytes)
				return chunks, nil
			})

		claimsStore.EXPECT().Create(gomock.Any(), int32(10)).
			DoAndReturn(func(data *oidc4vp.ClaimData, profileReceivedClaimsDataTTL int32) (string, error) {
				assert.Equal(t, oidc4vp.ClaimData{
					EncryptedData: chunks,
				}, *data)
				return "claimsID", nil
			})

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		vc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)
		vcSD, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)
		ld, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
			verifiable.WithDisabledProofCheck())
		assert.NoError(t, err)

		err = manager.StoreReceivedClaims("txID", &oidc4vp.ReceivedClaims{
			Credentials: []*verifiable.Credential{
				vc,
				vcSD,
				ld,
			},
		}, 20, 10)

		require.NoError(t, err)
	})

	t.Run("Fail encrypt", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("can not encrypt"))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.StoreReceivedClaims("txID", &oidc4vp.ReceivedClaims{
			Credentials: []*verifiable.Credential{},
		}, 20, 10)

		require.ErrorContains(t, err, "can not encrypt")
	})

	t.Run("Fail create", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			Return(nil, nil)
		claimsStore.EXPECT().Create(gomock.Any(), int32(10)).Return("", errors.New("can not store claims"))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.StoreReceivedClaims("txID", &oidc4vp.ReceivedClaims{
			Credentials: []*verifiable.Credential{},
		}, 20, 10)

		require.ErrorContains(t, err, "can not store claims")
	})
}

func TestTxManagerDeleteReceivedClaims(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		claimsStore.EXPECT().Delete(gomock.Any()).Return(nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.DeleteReceivedClaims("claimsID")
		require.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		claimsStore.EXPECT().Delete(gomock.Any()).Return(fmt.Errorf("delete error"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.DeleteReceivedClaims("claimsID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete error")
	})
}

func TestTxManagerDeleteTransaction(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		txID := oidc4vp.TxID(uuid.NewString())

		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Delete(txID).Return(nil)

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.Delete(txID)
		require.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		txID := oidc4vp.TxID(uuid.NewString())

		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Delete(txID).Return(errors.New("some error"))

		claimsStore := NewMockTxClaimsStore(gomock.NewController(t))
		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		crypto := NewMockDataProtector(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, claimsStore, crypto,
			testutil.DocumentLoader(t))

		err := manager.Delete(txID)
		require.Contains(t, err.Error(), "some error")
	})
}

func TestClaimsToRaw(t *testing.T) {
	t.Run("data nil", func(t *testing.T) {
		manager := oidc4vp.NewTxManager(nil, nil, nil, nil,
			testutil.DocumentLoader(t))

		resp, err := manager.ClaimsToClaimsRaw(nil)
		assert.NoError(t, err)
		assert.Nil(t, resp)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("data nil", func(t *testing.T) {
		manager := oidc4vp.NewTxManager(nil, nil, nil, nil,
			testutil.DocumentLoader(t))

		resp, err := manager.EncryptClaims(context.TODO(), nil)
		assert.NoError(t, err)
		assert.Nil(t, resp)
	})

	t.Run("encrypt err", func(t *testing.T) {
		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("encrypt err"))
		manager := oidc4vp.NewTxManager(nil, nil, nil, crypto,
			testutil.DocumentLoader(t))

		resp, err := manager.EncryptClaims(context.TODO(), &oidc4vp.ReceivedClaims{})
		assert.ErrorContains(t, err, "encrypt err")
		assert.Nil(t, resp)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("decrypt err", func(t *testing.T) {
		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("decrypt err"))
		manager := oidc4vp.NewTxManager(nil, nil, nil, crypto,
			testutil.DocumentLoader(t))

		resp, err := manager.DecryptClaims(context.TODO(), &oidc4vp.ClaimData{})
		assert.ErrorContains(t, err, "decrypt err")
		assert.Nil(t, resp)
	})

	t.Run("invalid json", func(t *testing.T) {
		crypto := NewMockDataProtector(gomock.NewController(t))
		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return([]byte("{"), nil)
		manager := oidc4vp.NewTxManager(nil, nil, nil, crypto,
			testutil.DocumentLoader(t))

		resp, err := manager.DecryptClaims(context.TODO(), &oidc4vp.ClaimData{})
		assert.ErrorContains(t, err,
			"can not unmarshal to ReceivedClaimsRaw, err: unexpected end of JSON input")
		assert.Nil(t, resp)
	})

	t.Run("invalid credential", func(t *testing.T) {
		raw := oidc4vp.ReceivedClaimsRaw{
			Credentials: [][]byte{
				{0x0, 0x3},
			},
		}
		dec, _ := json.Marshal(raw)
		crypto := NewMockDataProtector(gomock.NewController(t))

		crypto.EXPECT().Decrypt(gomock.Any(), gomock.Any()).
			Return(dec, nil)
		manager := oidc4vp.NewTxManager(nil, nil, nil, crypto,
			testutil.DocumentLoader(t))

		resp, err := manager.DecryptClaims(context.TODO(), &oidc4vp.ClaimData{})
		assert.ErrorContains(t, err,
			"received claims deserialize failed: unsupported credential format")
		assert.Nil(t, resp)
	})
}
