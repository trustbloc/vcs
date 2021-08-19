/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"testing"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/ld"
)

func TestNewStoreProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := ld.NewStoreProvider(mockstorage.NewMockStoreProvider())

		require.NotNil(t, provider)
		require.NoError(t, err)
	})

	t.Run("Fail to create JSON-LD context store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.FailNamespace = ldstore.ContextStoreName

		provider, err := ld.NewStoreProvider(storageProvider)

		require.Nil(t, provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create JSON-LD context store")
	})

	t.Run("Fail to create remote provider store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.FailNamespace = ldstore.RemoteProviderStoreName

		provider, err := ld.NewStoreProvider(storageProvider)

		require.Nil(t, provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create remote provider store")
	})
}

func TestStoreProvider_JSONLDContextStore(t *testing.T) {
	provider, err := ld.NewStoreProvider(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	require.NotNil(t, provider.JSONLDContextStore())
}

func TestStoreProvider_JSONLDRemoteProviderStore(t *testing.T) {
	provider, err := ld.NewStoreProvider(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	require.NotNil(t, provider.JSONLDRemoteProviderStore())
}
