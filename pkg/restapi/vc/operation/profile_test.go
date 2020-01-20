/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Run("test save profile success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewProfile(store)
		require.NotNil(t, record)

		issueDate := time.Now().UTC()
		value := &ProfileResponse{
			ID:        uuid.New().String(),
			URI:       "https://example.com/credentials/1872",
			IssueDate: &issueDate,
		}

		err := record.SaveProfile(value)
		require.NoError(t, err)

		require.NotEmpty(t, store)
		k := fmt.Sprintf(keyPattern, profileKeyPrefix, value.ID)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})
}

func TestCredentialRecord_GetProfile(t *testing.T) {
	t.Run("test get profile success", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewProfile(store)
		require.NotNil(t, record)

		issueDate := time.Now().UTC()
		valueStored := &ProfileResponse{
			ID:        uuid.New().String(),
			URI:       "https://example.com/credentials/1872",
			IssueDate: &issueDate,
		}

		err := record.SaveProfile(valueStored)
		require.NoError(t, err)

		require.NotEmpty(t, store)

		valueFound, err := record.GetProfile(valueStored.ID)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get profile failure due to invalid id", func(t *testing.T) {
		store := &mockstorage.MockStore{Store: make(map[string][]byte)}
		record := NewProfile(store)
		require.NotNil(t, record)

		profileByte, err := record.GetProfile("")
		require.Nil(t, profileByte)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store does not have a value associated with this key")
	})
}
