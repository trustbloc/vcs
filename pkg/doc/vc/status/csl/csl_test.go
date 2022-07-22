/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csl

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/vcs/pkg/doc/vc/profile"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

const (
	credID               = "http://example.edu/credentials/1872"
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
		s, err := New(&ariesmockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("error open"),
		}, 0, nil, nil)
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "error open")
	})
}

func validateVCStatus(t *testing.T, s *CredentialStatusManager, id string, index int) {
	t.Helper()

	status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
	require.NoError(t, err)
	require.Equal(t, StatusList2021Entry, status.Type)
	require.Equal(t, "revocation", status.CustomFields[StatusPurpose].(string))

	revocationListIndex, err := strconv.Atoi(status.CustomFields[StatusListIndex].(string))
	require.NoError(t, err)
	require.Equal(t, index, revocationListIndex)
	require.Equal(t, id, status.CustomFields[StatusListCredential].(string))

	revocationListVCBytes, err := s.GetRevocationListVC(id)
	require.NoError(t, err)
	revocationListVC, err := verifiable.ParseCredential(revocationListVCBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(revocationListVCBytes, &revocationListVC))
	require.Equal(t, id, revocationListVC.ID)
	require.Equal(t, "did:test:abc", revocationListVC.Issuer.ID)
	require.Equal(t, vcContext, revocationListVC.Context[0])
	require.Equal(t, Context, revocationListVC.Context[1])
	credSubject, ok := revocationListVC.Subject.([]verifiable.Subject)
	require.True(t, ok)
	require.Equal(t, id+"#list", credSubject[0].ID)
	require.Equal(t, revocationList2021Type, credSubject[0].CustomFields["type"].(string))
	require.Equal(t, "revocation", credSubject[0].CustomFields["statusPurpose"].(string))
	require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
	bitString, err := utils.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	require.NoError(t, err)
	bitSet, err := bitString.Get(revocationListIndex)
	require.NoError(t, err)
	require.False(t, bitSet)
}

func TestCredentialStatusList_CreateStatusID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		validateVCStatus(t, s, "localhost:8080/status/1", 0)
		validateVCStatus(t, s, "localhost:8080/status/1", 1)
		validateVCStatus(t, s, "localhost:8080/status/2", 0)
	})

	t.Run("test error from get latest id from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
			ErrGet: fmt.Errorf("get error"),
		}}, 1,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{}, &vdrmock.MockVDRegistry{},
				loader), loader)
		require.NoError(t, err)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest id to store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
			ErrGet: storage.ErrDataNotFound,
			ErrPut: fmt.Errorf("put error"),
		}}, 1,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{}, &vdrmock.MockVDRegistry{},
				loader), loader)
		require.NoError(t, err)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&storeProvider{store: &mockStore{
			getFunc: func(k string) ([]byte, error) {
				return nil, storage.ErrDataNotFound
			},
			putFunc: func(k string, v []byte) error {
				if k == "localhost:8080/status/1" {
					return fmt.Errorf("put error")
				}
				return nil
			},
		}}, 1,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store csl in store")
	})

	t.Run("test error from put latest id to store after store new list", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&storeProvider{store: &mockStore{
			getFunc: func(k string) ([]byte, error) {
				return nil, storage.ErrDataNotFound
			},
			putFunc: func(k string, v []byte) error {
				if k == latestListID && string(v) == "2" {
					return fmt.Errorf("put error")
				}
				return nil
			},
		}}, 1,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})
}

func TestCredentialStatusList_GetRevocationListVC(t *testing.T) {
	t.Run("test error getting csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) ([]byte, error) {
			return nil, fmt.Errorf("get error")
		}}}, 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{}, &vdrmock.MockVDRegistry{},
				loader), loader)
		require.NoError(t, err)
		csl, err := s.GetRevocationListVC("1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get revocationListVC from store")
	})
}

func TestCredentialStatusList_RevokeVC(t *testing.T) {
	t.Run("test vc status not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status not exist")
	})

	t.Run("test vc status type not supported", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: "noMatch"}
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status noMatch not supported")
	})

	t.Run("test vc status statusListIndex not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: StatusList2021Entry}
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListIndex field not exist in vc status")
	})

	t.Run("test vc status statusListCredential not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{
			Type: StatusList2021Entry, CustomFields: map[string]interface{}{StatusListIndex: "1"},
		}
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListCredential field not exist in vc status")
	})

	t.Run("test vc status statusListCredential wrong value type", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: StatusList2021Entry, CustomFields: map[string]interface{}{
			StatusListIndex: "1", StatusListCredential: 1, StatusPurpose: "test",
		}}
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast status statusListCredential")
	})

	t.Run("test statusPurpose not exist", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: StatusList2021Entry, CustomFields: map[string]interface{}{
			StatusListIndex: "1", StatusListCredential: 1,
		}}
		err = s.UpdateVC(cred, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusPurpose field not exist in vc status")
	})

	t.Run("test success", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = status
		require.NoError(t, s.UpdateVC(cred, getTestProfile(), true))

		revocationListVCBytes, err := s.GetRevocationListVC(status.CustomFields[StatusListCredential].(string))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(status.CustomFields[StatusListIndex].(string))
		require.NoError(t, err)

		revocationListVC, err := verifiable.ParseCredential(revocationListVCBytes, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		credSubject, ok := revocationListVC.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
		bitString, err := utils.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
		require.NoError(t, err)
		bitSet, err := bitString.Get(revocationListIndex)
		require.NoError(t, err)
		require.True(t, bitSet)
	})

	t.Run("test error get csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&storeProvider{store: &mockStore{getFunc: func(k string) ([]byte, error) {
			return nil, fmt.Errorf("get error")
		}}}, 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		err = s.UpdateVC(&verifiable.Credential{
			ID: credID,
			Status: &verifiable.TypedID{
				ID: "test", Type: StatusList2021Entry,
				CustomFields: map[string]interface{}{
					StatusListCredential: "test",
					StatusListIndex:      "1",
					StatusPurpose:        "test",
				},
			},
		}, getTestProfile(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get csl from store")
	})

	t.Run("test error from sign status credential", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(ariesmockstorage.NewMockStoreProvider(), 2,
			vccrypto.New(&mockkms.KeyManager{}, &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")},
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)
		require.NoError(t, err)

		_, err = s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
	})
}

func TestPrepareSigningOpts(t *testing.T) {
	t.Parallel()

	t.Run("prepare signing opts", func(t *testing.T) {
		profile := &vcprofile.DataProfile{
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

				opts, err := prepareSigningOpts(profile, []verifiable.Proof{proof})

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
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
	}
}

// storeProvider mock store provider.
type storeProvider struct {
	store *mockStore
}

// OpenStore opens and returns a store for given name space.
func (p *storeProvider) OpenStore(name string) (storage.Store, error) {
	return p.store, nil
}

// GetOpenStores is not implemented.
func (p *storeProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

// SetStoreConfig always return a nil error.
func (p *storeProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return nil
}

// GetStoreConfig is not implemented.
func (p *storeProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

// Close closes all stores created under this store provider.
func (p *storeProvider) CloseStore(name string) error {
	return nil
}

// Close closes all stores created under this store provider.
func (p *storeProvider) Close() error {
	return nil
}

// mockStore mock store.
type mockStore struct {
	putFunc func(k string, v []byte) error
	getFunc func(k string) ([]byte, error)
}

// Put stores the key and the record.
func (s *mockStore) Put(k string, v []byte, tags ...storage.Tag) error {
	if s.putFunc != nil {
		return s.putFunc(k, v)
	}

	return nil
}

// GetTags is not implemented.
func (s *mockStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

// Batch is not implemented.
func (s *mockStore) Batch(operations []storage.Operation) error {
	panic("implement me")
}

// Flush is not implemented.
func (s *mockStore) Flush() error {
	panic("implement me")
}

// Close is not implemented.
func (s *mockStore) Close() error {
	panic("implement me")
}

// GetBulk gets bulk.
func (s *mockStore) GetBulk(k ...string) ([][]byte, error) {
	return nil, nil
}

// Get fetches the record based on key.
func (s *mockStore) Get(k string) ([]byte, error) {
	if s.getFunc != nil {
		return s.getFunc(k)
	}

	return nil, nil
}

// Query queries the store for data based on the provided query string, the format of
// which will be dependent on what the underlying store requires.
func (s *mockStore) Query(expression string, _ ...storage.QueryOption) (storage.Iterator, error) {
	return nil, nil
}

func (s *mockStore) Delete(k string) error {
	panic("implement me")
}

func createDIDDoc(didID string) *did.Doc { //nolint:unparam
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
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}
