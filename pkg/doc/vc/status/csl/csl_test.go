/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csl

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

func TestCredentialStatusList_New(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{ErrOpenStoreHandle: fmt.Errorf("error open")}, "", 0, nil)
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "error open")
	})
}

func TestCredentialStatusList_CreateStatusID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)
		require.Equal(t, CredentialStatusType, status.Type)
		require.Equal(t, "localhost:8080/status/1", status.ID)
		csl, err := s.GetCSL("localhost:8080/status/1")
		require.NoError(t, err)
		require.Equal(t, len(csl.VC), 0)

		status, err = s.CreateStatusID()
		require.NoError(t, err)
		require.Equal(t, CredentialStatusType, status.Type)
		require.Equal(t, "localhost:8080/status/1", status.ID)
		csl, err = s.GetCSL("localhost:8080/status/1")
		require.NoError(t, err)
		require.Equal(t, len(csl.VC), 0)

		status, err = s.CreateStatusID()
		require.NoError(t, err)
		require.Equal(t, CredentialStatusType, status.Type)
		require.Equal(t, "localhost:8080/status/2", status.ID)
		csl, err = s.GetCSL("localhost:8080/status/2")
		require.NoError(t, err)
		require.Equal(t, len(csl.VC), 0)
	})

	t.Run("test error from get latest id from store", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, fmt.Errorf("get error")
		},
		}}, "localhost:8080/status", 1,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest id to store", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, storage.ErrValueNotFound
		},
			putFunc: func(k string, v []byte) error {
				return fmt.Errorf("put error")
			},
		}}, "localhost:8080/status", 1,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, storage.ErrValueNotFound
		},
			putFunc: func(k string, v []byte) error {
				if k == "localhost:8080/status/1" {
					return fmt.Errorf("put error")
				}
				return nil
			},
		}}, "localhost:8080/status", 1,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store csl in store")
	})

	t.Run("test error from put latest id to store after store new list", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, storage.ErrValueNotFound
		},
			putFunc: func(k string, v []byte) error {
				if k == latestListID && string(v) == "2" {
					return fmt.Errorf("put error")
				}
				return nil
			},
		}}, "localhost:8080/status", 1,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})
}

func TestCredentialStatusList_GetCSL(t *testing.T) {
	t.Run("test error getting csl from store", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, fmt.Errorf("get error")
		}}}, "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)
		csl, err := s.GetCSL("1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "ailed to get csl from store")
	})
}

func TestCredentialStatusList_UpdateVCStatus(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{Value: []byte(pubKey)}, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)

		statusValue := []string{"Revoked", "Revoked1"}

		for _, v := range statusValue {
			require.NoError(t, s.UpdateVCStatus(&verifiable.Credential{ID: "http://example.edu/credentials/1872",
				Status: status}, getTestProfile(),
				v, "Disciplinary action"))

			csl, err := s.GetCSL(status.ID)
			require.NoError(t, err)
			require.Equal(t, 1, len(csl.VC))
			require.Contains(t, csl.VC[0], "http://example.edu/credentials/1872")
			require.Contains(t, csl.VC[0], v)
			require.Contains(t, csl.VC[0], "Disciplinary action")
		}
	})

	t.Run("test error get csl from store", func(t *testing.T) {
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) (bytes []byte, err error) {
			return nil, fmt.Errorf("get error")
		}}}, "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		err = s.UpdateVCStatus(&verifiable.Credential{ID: "http://example.edu/credentials/1872",
			Status: &verifiable.TypedID{ID: "test"}}, getTestProfile(),
			"Revoked", "Disciplinary action")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get csl from store")
	})

	t.Run("test error from creating new status credential", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return nil, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)

		err = s.UpdateVCStatus(&verifiable.Credential{ID: "1872",
			Status: status}, getTestProfile(),
			"Revoked", "Disciplinary action")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new credential")
	})

	t.Run("test error from sign status credential", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kmsmock.CloseableKMS{SignMessageErr: fmt.Errorf("sign error")},
				&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{Value: []byte(pubKey)}, nil
				}}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)

		err = s.UpdateVCStatus(&verifiable.Credential{ID: "http://example.edu/credentials/1872",
			Status: status}, getTestProfile(),
			"Revoked", "Disciplinary action")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
	})
}

func getTestProfile() *vcprofile.DataProfile {
	return &vcprofile.DataProfile{
		Name:          "test",
		DID:           "did:test:abc",
		URI:           "https://test.com/credentials",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
	}
}

type mockKeyResolver struct {
	publicKeyFetcherValue verifiable.PublicKeyFetcher
}

func (m *mockKeyResolver) PublicKeyFetcher() verifiable.PublicKeyFetcher {
	return m.publicKeyFetcherValue
}

// storeProvider mock store provider.
type storeProvider struct {
	store *mockStore
}

func (p *storeProvider) CreateStore(name string) error {
	return nil
}

// OpenStore opens and returns a store for given name space.
func (p *storeProvider) OpenStore(name string) (storage.Store, error) {
	return p.store, nil
}

// Close closes all stores created under this store provider
func (p *storeProvider) CloseStore(name string) error {
	return nil
}

// Close closes all stores created under this store provider
func (p *storeProvider) Close() error {
	return nil
}

// mockStore mock store.
type mockStore struct {
	putFunc func(k string, v []byte) error
	getFunc func(k string) ([]byte, error)
}

// Put stores the key and the record
func (s *mockStore) Put(k string, v []byte) error {
	if s.putFunc != nil {
		return s.putFunc(k, v)
	}

	return nil
}

// Get fetches the record based on key
func (s *mockStore) Get(k string) ([]byte, error) {
	if s.getFunc != nil {
		return s.getFunc(k)
	}

	return nil, nil
}

// CreateIndex creates an index in the store based on the provided CreateIndexRequest.
func (s *mockStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return nil
}

// Query queries the store for data based on the provided query string, the format of
// which will be dependent on what the underlying store requires.
func (s *mockStore) Query(query string) (storage.ResultsIterator, error) {
	return nil, nil
}
