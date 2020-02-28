/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Run("test save profile success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := New(store)
		require.NotNil(t, record)

		created := time.Now().UTC()

		value := &DataProfile{
			Name:    "issuer",
			URI:     "https://example.com/credentials/1872",
			Created: &created,
		}

		err := record.SaveProfile(value)
		require.NoError(t, err)

		require.NotEmpty(t, store)
		k := fmt.Sprintf(keyPattern, profileKeyPrefix, value.Name)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})
}

func TestCredentialRecord_GetProfile(t *testing.T) {
	t.Run("test get profile success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := New(store)
		require.NotNil(t, record)

		created := time.Now().UTC()
		valueStored := &DataProfile{
			Name:          "issuer",
			URI:           "https://example.com/credentials",
			Created:       &created,
			DID:           "did",
			DIDPrivateKey: "privateKey",
		}

		err := record.SaveProfile(valueStored)
		require.NoError(t, err)

		require.NotEmpty(t, store)

		valueFound, err := record.GetProfile(valueStored.Name)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get profile failure due to invalid id", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := New(store)
		require.NotNil(t, record)

		profileByte, err := record.GetProfile("")
		require.Nil(t, profileByte)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store does not have a value associated with this key")
	})
}
