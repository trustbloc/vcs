/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/oidc"
)

type transaction struct {
	Name string `json:"name"`
}

func TestTxManager_CreateTx(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().SetIfNotExist(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(true, nil)

		manager := oidc.NewTxManager[transaction](store, 100*time.Second)

		id, err := manager.CreateTx("client1", &transaction{})

		require.NotEmpty(t, id)
		require.NoError(t, err)
	})

	t.Run("Fail", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().SetIfNotExist(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(1).Return(false, errors.New("test error"))

		manager := oidc.NewTxManager[transaction](store, 100*time.Second)

		_, err := manager.CreateTx("client1", &transaction{})

		require.Contains(t, err.Error(), "test error")
	})
}

func TestTxManager_GetByOneTimeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		expected := &transaction{
			Name: "test123",
		}
		expectedBytes, err := json.Marshal(expected)
		require.NoError(t, err)

		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().GetAndDelete(gomock.Any()).Times(1).Return(expectedBytes, true, nil)

		manager := oidc.NewTxManager[transaction](store, 100*time.Second)

		result := &transaction{}
		exists, err := manager.GetByOneTimeToken("client1", "test_nonce", result)

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, expected.Name, result.Name)
	})

	t.Run("Fail GetAndDelete", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().GetAndDelete(gomock.Any()).Times(1).Return(nil, true, errors.New("test error 123"))

		manager := oidc.NewTxManager[transaction](store, 100*time.Second)

		exists, err := manager.GetByOneTimeToken("client1", "test_nonce", &transaction{})

		require.False(t, exists)
		require.Contains(t, err.Error(), "test error 123")
	})

	t.Run("Fail unmarshal", func(t *testing.T) {
		store := NewMockTxStore(gomock.NewController(t))
		store.EXPECT().GetAndDelete(gomock.Any()).Times(1).Return([]byte(","), true, nil)

		manager := oidc.NewTxManager[transaction](store, 100*time.Second)

		_, err := manager.GetByOneTimeToken("client1", "test_nonce", &transaction{})

		require.Contains(t, err.Error(), "invalid character")
	})
}
