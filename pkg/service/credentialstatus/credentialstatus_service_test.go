/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/trustbloc/vcs/pkg/kms/signer"

	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"

	"github.com/trustbloc/vcs/pkg/doc/vc"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
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

func validateVCStatus(t *testing.T, s *Service, id string, index int) {
	t.Helper()

	status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
	require.NoError(t, err)
	require.Equal(t, StatusList2021Entry, status.Type)
	require.Equal(t, "revocation", status.CustomFields[StatusPurpose].(string))

	revocationListIndex, err := strconv.Atoi(status.CustomFields[StatusListIndex].(string))
	require.NoError(t, err)
	require.Equal(t, index, revocationListIndex)
	require.Equal(t, id, status.CustomFields[StatusListCredential].(string))

	revocationListVC, err := s.GetRevocationListVC(id)
	require.NoError(t, err)
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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		validateVCStatus(t, s, "localhost:8080/status/1", 0)
		validateVCStatus(t, s, "localhost:8080/status/1", 1)
		validateVCStatus(t, s, "localhost:8080/status/2", 0)
	})

	t.Run("test error from get latest id from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(newMockCSLStore(func(store *mockCSLStore) {
			store.getLatestListIDErr = errors.New("some error")
		}), newMockVCStore(), 1,
			vccrypto.New(&vdrmock.MockVDRegistry{},
				loader), loader)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest id to store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(newMockCSLStore(
			func(store *mockCSLStore) {
				store.createLatestListIDErr = errors.New("some error")
			}), newMockVCStore(), 1,
			vccrypto.New(&vdrmock.MockVDRegistry{},
				loader), loader)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(newMockCSLStore(
			func(store *mockCSLStore) {
				store.createErr = errors.New("some error")
			}), newMockVCStore(), 1,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store csl in store")
	})

	t.Run("test error from put latest id to store after store new list", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(newMockCSLStore(
			func(store *mockCSLStore) {
				store.updateLatestListIDErr = errors.New("some error")
			}), newMockVCStore(), 1,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})
}

func TestCredentialStatusList_GetRevocationListVC(t *testing.T) {
	t.Run("test error getting csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(newMockCSLStore(
			func(store *mockCSLStore) {
				store.findErr = errors.New("some error")
			}), newMockVCStore(), 2,
			vccrypto.New(&vdrmock.MockVDRegistry{},
				loader), loader)

		csl, err := s.GetRevocationListVC("1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get revocationListVC from store")
	})
}

func TestCredentialStatusList_RevokeVC(t *testing.T) {
	t.Run("UpdateVCStatus success", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		s := New(newMockCSLStore(), vcStore, 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		profile := getTestProfile()
		status, err := s.CreateStatusID(profile, "localhost:8080/status")
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = status

		err = vcStore.Put("testprofile", cred)
		require.NoError(t, err)

		require.NoError(t, s.UpdateVCStatus(getTestProfile(), "testprofile", cred.ID, "true"))

		revocationListVC, err := s.GetRevocationListVC(status.CustomFields[StatusListCredential].(string))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(status.CustomFields[StatusListIndex].(string))
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

	t.Run("UpdateVCStatus store.Get error", func(t *testing.T) {
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			nil, nil)

		err := s.UpdateVCStatus(getTestProfile(), "testprofile", "testId", "true")
		require.Error(t, err)
		require.ErrorContains(t, err, "data not found")
	})

	t.Run("UpdateVCStatus ParseCredential error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		s := New(newMockCSLStore(), vcStore, 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.Context = append([]string{}, cred.Context[1:]...)

		err = vcStore.Put("testprofile", cred)
		require.NoError(t, err)

		err = s.UpdateVCStatus(getTestProfile(), "testprofile", cred.ID, "true")
		require.Error(t, err)
		require.ErrorContains(t, err, "verifiable credential is not valid")
	})

	t.Run("UpdateVCStatus ParseBool error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		s := New(newMockCSLStore(), vcStore, 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		err = vcStore.Put("testprofile", cred)
		require.NoError(t, err)

		err = s.UpdateVCStatus(getTestProfile(), "testprofile", cred.ID, "invalid")
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid syntax")
	})

	t.Run("test vc status not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		status, err := s.CreateStatusID(getTestProfile(), "localhost:8080/status")
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = status
		require.NoError(t, s.UpdateVC(cred, getTestProfile(), true))

		revocationListVC, err := s.GetRevocationListVC(status.CustomFields[StatusListCredential].(string))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(status.CustomFields[StatusListIndex].(string))
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
		s := New(newMockCSLStore(func(store *mockCSLStore) {
			store.findErr = errors.New("some error")
		}), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		err := s.UpdateVC(&verifiable.Credential{
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
		s := New(newMockCSLStore(), newMockVCStore(), 2,
			vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader), loader)

		_, err := s.CreateStatusID(getTestSignerWithCrypto(
			&cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}), "localhost:8080/status")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
	})
}

func TestPrepareSigningOpts(t *testing.T) {
	t.Parallel()

	t.Run("prepare signing opts", func(t *testing.T) {
		profile := &vc.Signer{
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

func getTestProfile() *vc.Signer {
	return &vc.Signer{
		Format:        vcsverifiable.Ldp,
		DID:           "did:test:abc",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
		KMS:           &mockKMS{},
	}
}

func getTestSignerWithCrypto(crypto ariescrypto.Crypto) *vc.Signer {
	return &vc.Signer{
		Format:        vcsverifiable.Ldp,
		DID:           "did:test:abc",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
		KMS:           &mockKMS{crypto: crypto},
	}
}

type mockCSLStore struct {
	createErr             error
	findErr               error
	getLatestListIDErr    error
	createLatestListIDErr error
	updateLatestListIDErr error
	latestListID          int
	s                     map[string]*CSLWrapper
}

func newMockCSLStore(opts ...func(*mockCSLStore)) *mockCSLStore {
	s := &mockCSLStore{
		latestListID: -1,
		s:            map[string]*CSLWrapper{},
	}
	for _, f := range opts {
		f(s)
	}
	return s
}

func (m *mockCSLStore) Upsert(cslWrapper *CSLWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslWrapper.VC.ID] = cslWrapper
	return nil
}

func (m *mockCSLStore) Get(id string) (*CSLWrapper, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}

	w, ok := m.s[id]
	if !ok {
		return nil, ErrDataNotFound
	}

	return w, nil
}
func (m *mockCSLStore) CreateLatestListID(id int) error {
	if m.createLatestListIDErr != nil {
		return m.createLatestListIDErr
	}

	m.latestListID = id

	return nil
}

func (m *mockCSLStore) UpdateLatestListID(id int) error {
	if m.updateLatestListIDErr != nil {
		return m.updateLatestListIDErr
	}
	return m.CreateLatestListID(id)
}

func (m *mockCSLStore) GetLatestListID() (int, error) {
	if m.getLatestListIDErr != nil {
		return -1, m.getLatestListIDErr
	}

	if m.latestListID == -1 {
		return -1, ErrDataNotFound
	}

	return m.latestListID, nil
}

type mockVCStore struct {
	s map[string]*verifiable.Credential
}

func newMockVCStore() *mockVCStore {
	return &mockVCStore{
		s: map[string]*verifiable.Credential{},
	}
}

func (m *mockVCStore) Get(profileName, vcID string) ([]byte, error) {
	v, ok := m.s[fmt.Sprintf("%s_%s", profileName, vcID)]
	if !ok {
		return nil, errors.New("data not found")
	}

	return v.MarshalJSON()
}

func (m *mockVCStore) Put(profileName string, vc *verifiable.Credential) error {
	m.s[fmt.Sprintf("%s_%s", profileName, vc.ID)] = vc
	return nil
}

type mockKMS struct {
	crypto ariescrypto.Crypto
}

func (m *mockKMS) NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if m.crypto == nil {
		m.crypto = &cryptomock.Crypto{}
	}

	return signer.NewKMSSigner(&mockkms.KeyManager{}, m.crypto, creator, signatureType)
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
