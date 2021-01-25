/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"errors"
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

const testProfileID = "testProfile"

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		record, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)
	})

	t.Run("test new - success", func(t *testing.T) {
		record, err := New(&ariesmockstorage.MockStoreProvider{ErrOpenStoreHandle: errors.New("db provider error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "db provider error")
		require.Nil(t, record)
	})

	t.Run("test new - success", func(t *testing.T) {
		record, err := New(&ariesmockstorage.MockStoreProvider{ErrOpenStoreHandle: errors.New("error opening the handler")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error opening the handler")
		require.Nil(t, record)
	})
}

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Run("test save profile - success", func(t *testing.T) {
		record, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{
			ID: "profile1",
		}

		err = record.SaveProfile(value)
		require.NoError(t, err)

		k := getDBKey(value.ID)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})
}

func TestGetProfile(t *testing.T) {
	t.Run("test get profile - success", func(t *testing.T) {
		s := make(map[string][]byte)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		profileData := &ProfileData{
			ID: "verifier-1",
		}

		profileJSON, err := json.Marshal(profileData)
		require.NoError(t, err)

		s[getDBKey(profileData.Name)] = profileJSON

		resp, err := profileStore.GetProfile(profileData.Name)
		require.NoError(t, err)

		require.Equal(t, profileData, resp)
	})

	t.Run("test get profile - no data", func(t *testing.T) {
		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: make(map[string][]byte)}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)
		require.NotNil(t, profileStore)

		resp, err := profileStore.GetProfile("verifier-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, resp)
	})

	t.Run("test get profile - invalid json", func(t *testing.T) {
		s := make(map[string][]byte)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		s[getDBKey("verifier-1")] = []byte("invalid-data")

		resp, err := profileStore.GetProfile("verifier-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, resp)
	})
}

func TestDeleteProfile(t *testing.T) {
	t.Run("test delete profile - success", func(t *testing.T) {
		mockStore, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, mockStore)

		value := &ProfileData{ID: testProfileID}
		err = mockStore.SaveProfile(value)
		require.NoError(t, err)

		err = mockStore.DeleteProfile(testProfileID)
		require.NoError(t, err)
	})
}
