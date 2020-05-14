/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/internal/mock/kms"
)

const (
	universityDegreeCred = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
 	"https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "id": "http://example.gov/credentials/3732",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "issuer": {
    "id": "did:example:oakek12as93mas91220dapop092",
    "name": "University"
  },
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "degree": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }
}`
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{}, &vdrimock.MockVDRIRegistry{}))
		require.NoError(t, err)
		csl, err := s.GetCSL("1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "ailed to get csl from store")
	})
}

func TestCredentialStatusList_UpdateVCStatus(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{},
				&vdrimock.MockVDRIRegistry{ResolveValue: createDIDDoc("did:test:abc")}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)

		statusValue := []string{"Revoked", "Revoked1"}

		cred, _, err := verifiable.NewCredential([]byte(universityDegreeCred))
		require.NoError(t, err)

		for _, v := range statusValue {
			cred.ID = "http://example.edu/credentials/1872"
			cred.Status = status
			require.NoError(t, s.UpdateVCStatus(cred, getTestProfile(), v, "Disciplinary action"))

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
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{},
				&vdrimock.MockVDRIRegistry{ResolveValue: createDIDDoc("did:test:abc")}))
		require.NoError(t, err)

		err = s.UpdateVCStatus(&verifiable.Credential{ID: "http://example.edu/credentials/1872",
			Status: &verifiable.TypedID{ID: "test"}}, getTestProfile(),
			"Revoked", "Disciplinary action")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get csl from store")
	})

	t.Run("test error from creating new status credential", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{},
				&vdrimock.MockVDRIRegistry{ResolveValue: createDIDDoc("did:test:abc")}))
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
		s, err := New(mockstore.NewMockStoreProvider(), "localhost:8080/status", 2,
			vccrypto.New(&kms.KeyManager{}, &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")},
				&vdrimock.MockVDRIRegistry{ResolveValue: createDIDDoc("did:test:abc")}))
		require.NoError(t, err)

		status, err := s.CreateStatusID()
		require.NoError(t, err)

		cred, _, err := verifiable.NewCredential([]byte(universityDegreeCred))
		require.NoError(t, err)
		cred.ID = "http://example.edu/credentials/1872"
		cred.Status = status

		err = s.UpdateVCStatus(cred, getTestProfile(),
			"Revoked", "Disciplinary action")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
	})
}

func TestPrepareSigningOpts(t *testing.T) {
	t.Run("prepare signing opts", func(t *testing.T) {
		profile := vcprofile.DataProfile{
			Creator: "did:creator#key-1",
		}

		tests := []struct {
			name   string
			proof  string
			result int
			count  int
			err    string
		}{
			{
				name: "prepare proofvalue signing opts",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"proofPurpose": "assertionMethod",
        				"proofValue": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8AUdCJDRptPkBuqAQ",
        				"type": "Ed25519Signature2018",
        				"verificationMethod": "did:trustbloc:testnet.trustbloc.local#key-1"
    				}`,
			},
			{
				name: "prepare jws signing opts",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"proofPurpose": "assertionMethod",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"type": "Ed25519Signature2018",
        				"verificationMethod": "did:creator#key-1"
    				}`,
				count: 3,
			},
			{
				name: "prepare signing opts from proof with 3 required properties",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"type": "Ed25519Signature2018",
        				"verificationMethod": "did:example:EiABBmUZ7JjpKSTNGq9Q==#key-1"
    				}`,
			},
			{
				name: "prepare signing opts from proof with 2 required properties",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"verificationMethod": "did:example:EiABBmUZ7JjpKSTNGq9Q==#key-1"
    				}`,
			},
			{
				name: "prepare signing opts from proof with 1 required property",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ"
    				}`,
			},
			{
				name: "prepare jws signing opts - invalid purpose",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"proofPurpose": {},
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"type": "Ed25519Signature2018",
        				"verificationMethod": "did:example:EiABBmUZ7JjpKSTNGq9Q==#key-1"
    				}`,
				err: "invalid 'proofPurpose' type",
			},
			{
				name: "prepare jws signing opts - invalid signature type",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"type": {},
        				"verificationMethod": "did:example:EiABBmUZ7JjpKSTNGq9Q==#key-1"
    				}`,
				err: "invalid 'type' type",
			},
			{
				name: "prepare jws signing opts - invalid signature type",
				proof: `{
        				"created": "2020-04-17T04:17:48Z",
        				"jws": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8ejsNbHZCJDRptPkBuqAQ",
        				"type": {},
        				"verificationMethod": {}
    				}`,
				err: "invalid 'verificationMethod' type",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var proof map[string]interface{}
				err := json.Unmarshal([]byte(tc.proof), &proof)
				require.NoError(t, err)

				opts, err := prepareSigningOpts(&profile, []verifiable.Proof{proof})

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				if tc.count > 0 {
					require.Len(t, opts, tc.count)
				}

				require.NoError(t, err)
				require.NotEmpty(t, opts)
			})
		}
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

// nolint: unparam
func createDIDDoc(didID string) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := didID + "#key1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		PublicKey:            []did.PublicKey{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.VerificationMethod{{PublicKey: signingKey}},
		Authentication:       []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityInvocation: []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityDelegation: []did.VerificationMethod{{PublicKey: signingKey}},
	}
}
