/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/ldstore"
)

const (
	providerEndpoint        = "https://example.com/ld-contexts.json"
	anotherProviderEndpoint = "https://another.example.com/ld-contexts.json"
)

func TestRemoteProviderStore(t *testing.T) {
	connectionString := "mongodb://localhost:27030"

	pool, mongoDBResource := startMongoDBContainer(t, connectionString, "27030")

	t.Cleanup(func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	})

	client, clientErr := mongodb.New(connectionString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, clientErr)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	t.Run("test store, retrieve and delete", func(t *testing.T) {
		store, err := ldstore.NewRemoteProviderStore(client)
		require.NoError(t, err)

		// create a new remote provider
		provider, err := store.Save(providerEndpoint)
		require.NoError(t, err)
		require.NotEmpty(t, provider.ID)
		require.Equal(t, providerEndpoint, provider.Endpoint)

		// provider already exists
		sameProvider, err := store.Save(providerEndpoint)
		require.NoError(t, err)
		require.Equal(t, provider.ID, sameProvider.ID)
		require.Equal(t, providerEndpoint, sameProvider.Endpoint)

		// retrieve the provider
		got, err := store.Get(provider.ID)
		require.NoError(t, err)
		require.Equal(t, provider.ID, got.ID)
		require.Equal(t, providerEndpoint, got.Endpoint)

		// add the second provider
		anotherProvider, err := store.Save(anotherProviderEndpoint)
		require.NoError(t, err)
		require.NotEmpty(t, anotherProvider.ID)
		require.Equal(t, anotherProviderEndpoint, anotherProvider.Endpoint)

		// retrieve all providers
		providers, err := store.GetAll()
		require.NoError(t, err)
		require.Equal(t, 2, len(providers))

		// delete the other provider
		err = store.Delete(anotherProvider.ID)
		require.NoError(t, err)

		providers, err = store.GetAll()
		require.NoError(t, err)
		require.Equal(t, 1, len(providers))
	})
}
