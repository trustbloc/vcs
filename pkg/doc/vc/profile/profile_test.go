/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Run("test save profile success", func(t *testing.T) {
		record, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		created := time.Now().UTC()

		value := &IssuerProfile{
			DataProfile: &DataProfile{
				Name:    "issuer",
				Created: &created,
			},
			URI: "https://example.com/credentials/1872",
		}

		err = record.SaveProfile(value)
		require.NoError(t, err)

		k := getDBKey(issuerMode, value.Name)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})
}

func TestCredentialRecord_GetProfile(t *testing.T) {
	t.Run("test get profile success", func(t *testing.T) {
		record, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		created := time.Now().UTC()
		valueStored := &IssuerProfile{
			DataProfile: &DataProfile{
				Name:                    "issuer",
				Created:                 &created,
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
			URI: "https://example.com/credentials",
		}

		err = record.SaveProfile(valueStored)
		require.NoError(t, err)

		valueFound, err := record.GetProfile(valueStored.Name)
		require.NoError(t, err)
		require.Equal(t, valueStored, valueFound)
	})

	t.Run("test get profile failure due to invalid id", func(t *testing.T) {
		record, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		profileByte, err := record.GetProfile("")
		require.Nil(t, profileByte)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})
}

func TestCredentialRecord_DeleteProfile(t *testing.T) {
	t.Run("test delete profile - success", func(t *testing.T) {
		mockStore, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, mockStore)

		created := time.Now().UTC()

		value := &IssuerProfile{
			DataProfile: &DataProfile{
				Name:    "issuer",
				Created: &created,
			},
			URI: "https://example.com/credentials/1872",
		}

		err = mockStore.SaveProfile(value)
		require.NoError(t, err)

		err = mockStore.DeleteProfile("issuer")
		require.NoError(t, err)
	})
}

func TestSaveHolder(t *testing.T) {
	t.Run("test save holder - success", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
			Store: s,
		}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		holderProfile := &HolderProfile{
			DataProfile: &DataProfile{
				Name:                    "holder-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		err = profileStore.SaveHolderProfile(holderProfile)
		require.NoError(t, err)

		require.Equal(t, 1, len(s))
	})

	t.Run("test save holder - fail", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: s, ErrPut: fmt.Errorf("put error")},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		holderProfile := &HolderProfile{
			DataProfile: &DataProfile{
				Name:                    "holder-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		err = profileStore.SaveHolderProfile(holderProfile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestDeleteHolderProfile(t *testing.T) {
	t.Run("test delete holder profile - success", func(t *testing.T) {
		mockStore, err := New(ariesmockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, mockStore)

		holderProfile := &HolderProfile{
			DataProfile: &DataProfile{
				Name:                    "holder-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}
		err = mockStore.SaveHolderProfile(holderProfile)
		require.NoError(t, err)

		err = mockStore.DeleteHolderProfile("holder-1")
		require.NoError(t, err)
	})
}

func TestSaveGovernance(t *testing.T) {
	t.Run("test save governance - success", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
			Store: s,
		}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		governanceProfile := &GovernanceProfile{
			DataProfile: &DataProfile{
				Name:                    "governance-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		err = profileStore.SaveGovernanceProfile(governanceProfile)
		require.NoError(t, err)

		require.Equal(t, 1, len(s))
	})

	t.Run("test save governance - fail", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: s, ErrPut: fmt.Errorf("put error")},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		governanceProfile := &GovernanceProfile{
			DataProfile: &DataProfile{
				Name:                    "governance-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		err = profileStore.SaveGovernanceProfile(governanceProfile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestGetHolder(t *testing.T) {
	t.Run("test get holder - success", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		holderProfile := &HolderProfile{
			DataProfile: &DataProfile{
				Name:                    "holder-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		profileJSON, err := json.Marshal(holderProfile)
		require.NoError(t, err)

		s[getDBKey(holderMode, holderProfile.Name)] = ariesmockstorage.DBEntry{Value: profileJSON}

		resp, err := profileStore.GetHolderProfile(holderProfile.Name)
		require.NoError(t, err)

		require.Equal(t, holderProfile, resp)
	})

	t.Run("test get holder - no data", func(t *testing.T) {
		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: make(map[string]ariesmockstorage.DBEntry)},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)
		require.NotNil(t, profileStore)

		resp, err := profileStore.GetHolderProfile("holder-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, resp)
	})

	t.Run("test get holder - invalid json", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: s},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		s[getDBKey(holderMode, "holder-1")] = ariesmockstorage.DBEntry{Value: []byte("invalid-data")}

		resp, err := profileStore.GetHolderProfile("holder-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, resp)
	})
}

func TestGovernanceHolder(t *testing.T) {
	t.Run("test get governance - success", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: s},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		governanceProfile := &GovernanceProfile{
			DataProfile: &DataProfile{
				Name:                    "governance-1",
				DID:                     "did",
				SignatureType:           "SignatureType",
				SignatureRepresentation: verifiable.SignatureProofValue,
			},
		}

		profileJSON, err := json.Marshal(governanceProfile)
		require.NoError(t, err)

		s[getDBKey(governanceMode, governanceProfile.Name)] = ariesmockstorage.DBEntry{Value: profileJSON}

		resp, err := profileStore.GetGovernanceProfile(governanceProfile.Name)
		require.NoError(t, err)

		require.Equal(t, governanceProfile, resp)
	})

	t.Run("test get governance - no data", func(t *testing.T) {
		profileStore, err := New(&ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: make(map[string]ariesmockstorage.DBEntry)},
		})
		require.NoError(t, err)
		require.NotNil(t, profileStore)
		require.NotNil(t, profileStore)

		resp, err := profileStore.GetGovernanceProfile("governance-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, resp)
	})

	t.Run("test get governance - invalid json", func(t *testing.T) {
		s := make(map[string]ariesmockstorage.DBEntry)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		s[getDBKey(governanceMode, "governance-1")] = ariesmockstorage.DBEntry{Value: []byte("invalid-data")}

		resp, err := profileStore.GetGovernanceProfile("governance-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, resp)
	})
}
