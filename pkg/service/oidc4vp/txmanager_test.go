/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

func TestTxManager_CreateTx(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(oidc4vp.TxID("txID"), nil)
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(&oidc4vp.Transaction{ID: "txID", ProfileID: "org_id"}, nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().SetIfNotExist(gomock.Any(), oidc4vp.TxID("txID"), 100*time.Second).Times(1).Return(true, nil)

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		tx, nonce, err := manager.CreateTx(&presexch.PresentationDefinition{}, "org_id")

		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(oidc4vp.TxID(""), errors.New("test error"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, _, err := manager.CreateTx(&presexch.PresentationDefinition{}, "org_id")

		require.Contains(t, err.Error(), "test error")
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(oidc4vp.TxID("txID"), nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().SetIfNotExist(gomock.Any(), oidc4vp.TxID("txID"), 100*time.Second).
			Times(1).Return(false, errors.New("test error"))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, _, err := manager.CreateTx(&presexch.PresentationDefinition{}, "org_id")

		require.Contains(t, err.Error(), "test error")
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(oidc4vp.TxID("txID"), nil)
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, errors.New("test error"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().SetIfNotExist(gomock.Any(), oidc4vp.TxID("txID"), 100*time.Second).Times(1).Return(true, nil)

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, _, err := manager.CreateTx(&presexch.PresentationDefinition{}, "org_id")

		require.Contains(t, err.Error(), "test error")
	})
}

func TestTxManager_GetByOneTimeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(&oidc4vp.Transaction{ID: "txID", ProfileID: "org_id"}, nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete("nonce").Times(1).Return(oidc4vp.TxID("txID"), true, nil)

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		tx, exists, err := manager.GetByOneTimeToken("nonce")

		require.NoError(t, err)
		require.True(t, exists)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
	})

	t.Run("Fail GetAndDelete", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete(gomock.Any()).Times(1).Return(oidc4vp.TxID(""), true, errors.New("test error 123"))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, exists, err := manager.GetByOneTimeToken("nonce")

		require.False(t, exists)
		require.Contains(t, err.Error(), "test error 123")
	})

	t.Run("Fail Get", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, errors.New("test error 333"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))
		nonceStore.EXPECT().GetAndDelete("nonce").Times(1).Return(oidc4vp.TxID("txID"), true, nil)

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, exists, err := manager.GetByOneTimeToken("nonce")

		require.False(t, exists)
		require.Contains(t, err.Error(), "test error 333")
	})
}

func TestTxManager_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(&oidc4vp.Transaction{ID: "txID", ProfileID: "org_id"}, nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		tx, err := manager.Get("txID")

		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "org_id", tx.ProfileID)
	})

	t.Run("Fail Get", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Get(oidc4vp.TxID("txID")).Return(nil, errors.New("test error 333"))

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		_, err := manager.Get("txID")

		require.Contains(t, err.Error(), "test error 333")
	})
}

func TestTxManagerStoreReceivedClaims(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().Update(gomock.Any()).Return(nil)

		nonceStore := NewMockTxNonceStore(gomock.NewController(t))

		manager := oidc4vp.NewTxManager(nonceStore, store, 100*time.Second)

		err := manager.StoreReceivedClaims("txID", &oidc4vp.ReceivedClaims{})

		require.NoError(t, err)
	})
}
