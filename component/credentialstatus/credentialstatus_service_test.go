/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	vdr2 "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/component/credentialstatus/internal/testutil"
	"github.com/trustbloc/vcs/component/credentialstatus/statustype"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cslstore"
)

const (
	profileID            = "testProfileID"
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

func validateVCStatus(t *testing.T, s *Service, expectedStatusListVCID string, expectedRevocationIndex int) {
	t.Helper()

	statusID, err := s.CreateStatusID(profileID)
	require.NoError(t, err)
	require.Equal(t, string(vc.StatusList2021VCStatus), statusID.VCStatus.Type)
	require.Equal(t, "revocation", statusID.VCStatus.CustomFields[statustype.StatusPurpose].(string))

	revocationListIndex, err := strconv.Atoi(statusID.VCStatus.CustomFields[statustype.StatusListIndex].(string))
	require.NoError(t, err)
	require.Equal(t, expectedRevocationIndex, revocationListIndex)
	require.Equal(t, expectedStatusListVCID, statusID.VCStatus.CustomFields[statustype.StatusListCredential].(string))

	chunks := strings.Split(expectedStatusListVCID, "/")
	statusVCID := chunks[len(chunks)-1]

	statusListVC, err := s.GetStatusListVC(profileID, statusVCID)
	require.NoError(t, err)
	require.Equal(t, expectedStatusListVCID, statusListVC.ID)
	require.Equal(t, "did:test:abc", statusListVC.Issuer.ID)
	require.Equal(t, vcutil.DefVCContext, statusListVC.Context[0])
	require.Equal(t, statustype.StatusList2021Context, statusListVC.Context[1])
	credSubject, ok := statusListVC.Subject.([]verifiable.Subject)
	require.True(t, ok)
	require.Equal(t, expectedStatusListVCID+"#list", credSubject[0].ID)
	require.Equal(t, statustype.StatusList2021VCSubjectType, credSubject[0].CustomFields["type"].(string))
	require.Equal(t, "revocation", credSubject[0].CustomFields[statustype.StatusPurpose].(string))
	require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
	bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	require.NoError(t, err)
	bitSet, err := bitString.Get(revocationListIndex)
	require.NoError(t, err)
	require.False(t, bitSet)
}

func TestCredentialStatusList_CreateStatusID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(3).Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		validateVCStatus(t, s, "https://localhost:8080/issuer/profiles/testProfileID/credentials/status/1", 0)
		validateVCStatus(t, s, "https://localhost:8080/issuer/profiles/testProfileID/credentials/status/1", 1)
		validateVCStatus(t, s, "https://localhost:8080/issuer/profiles/testProfileID/credentials/status/2", 0)
	})

	t.Run("test error get profile service", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, errors.New("some error"))

		s := New(&Config{
			ProfileService: mockProfileSrv,
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get profile")
	})

	t.Run("test error get key manager", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(getTestProfile(), nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, errors.New("some error"))

		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get kms")
	})

	t.Run("test error get status processor", func(t *testing.T) {
		profile := getTestProfile()
		profile.VCConfig.Status.Type = "undefined"
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(profile, nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "unsupported VCStatusListType")
	})

	t.Run("test error get status list vc url", func(t *testing.T) {
		profile := getTestProfile()
		profile.URL = " https://example.com"
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(profile, nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to create status URL")
	})

	t.Run("test error from get latest id from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(func(store *mockCSLStore) {
				store.getLatestListIDErr = errors.New("some error")
			}),
			VCStore:        nil,
			ListSize:       1,
			KMSRegistry:    mockKMSRegistry,
			ProfileService: mockProfileSrv,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest id to store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.createLatestListIDErr = errors.New("some error")
				}),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			ListSize:       1,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.createErr = errors.New("some error")
				}),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       1,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store csl in store")
	})

	t.Run("test error from put latest id to store after store new list", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.updateLatestListIDErr = errors.New("some error")
				}),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       1,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		status, err := s.CreateStatusID(profileID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})
}

func TestCredentialStatusList_GetStatusListVC(t *testing.T) {
	t.Run("test error get profile", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))

		s := New(&Config{
			ProfileService: mockProfileSrv,
		})
		csl, err := s.GetStatusListVC(profileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get profile")
	})
	t.Run("test error get status list vc url", func(t *testing.T) {
		profile := getTestProfile()
		profile.URL = " https://example.com"
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(profile, nil)

		s := New(&Config{
			ProfileService: mockProfileSrv,
		})
		csl, err := s.GetStatusListVC(profileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get status URL")
	})
	t.Run("test error getting csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.findErr = errors.New("some error")
				}),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			ListSize:       2,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		csl, err := s.GetStatusListVC(profileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get revocationListVC from store")
	})
}

func TestCredentialStatusList_RevokeVC(t *testing.T) {
	t.Run("UpdateVCStatus success", func(t *testing.T) {
		profile := getTestProfile()
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(profile, nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStore:        vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		statusID, err := s.CreateStatusID(profileID)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = statusID.VCStatus

		err = vcStore.Put(profile.Name, cred)
		require.NoError(t, err)

		require.NoError(t, s.UpdateVCStatus(profileID, cred.ID, "true", profile.VCConfig.Status.Type))

		statusListVC, err := s.GetStatusListVC(profileID, "1")
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusID.VCStatus.CustomFields[statustype.StatusListIndex].(string))
		require.NoError(t, err)

		credSubject, ok := statusListVC.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
		bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
		require.NoError(t, err)
		bitSet, err := bitString.Get(revocationListIndex)
		require.NoError(t, err)
		require.True(t, bitSet)
	})
	t.Run("UpdateVCStatus profileService.GetProfile error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		s := New(&Config{
			ProfileService: mockProfileSrv,
		})

		err := s.UpdateVCStatus(profileID, "testID", "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get profile")
	})
	t.Run("UpdateVCStatus invalid vc status type error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		s := New(&Config{
			ProfileService: mockProfileSrv,
		})

		err := s.UpdateVCStatus(profileID, "testID", "true", vc.RevocationList2020VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "not supported by current profile")
	})
	t.Run("UpdateVCStatus kmsRegistry.GetKeyManager error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})

		err := s.UpdateVCStatus(profileID, "testID", "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get kms")
	})
	t.Run("UpdateVCStatus store.Get error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
		})

		err := s.UpdateVCStatus(profileID, "testprofile", "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "data not found")
	})

	t.Run("UpdateVCStatus ParseCredential error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        vcStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.Context = append([]string{}, cred.Context[1:]...)

		err = vcStore.Put("testprofile", cred)
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, cred.ID, "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "verifiable credential is not valid")
	})

	t.Run("UpdateVCStatus ParseBool error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStore:        vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		err = vcStore.Put("testprofile", cred)
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, cred.ID, "undefined", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid syntax")
	})

	t.Run("test vc status not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status not exist")
	})

	t.Run("test vc status type not supported", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: "noMatch"}
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status noMatch not supported")
	})

	t.Run("test vc status statusListIndex not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)}
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListIndex field not exist in vc status")
	})

	t.Run("test vc status statusListCredential not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{
			Type:         string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{statustype.StatusListIndex: "1"},
		}
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListCredential field not exist in vc status")
	})

	t.Run("test vc status statusListCredential wrong value type", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{
			Type: string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{
				statustype.StatusListIndex:      "1",
				statustype.StatusListCredential: 1,
				statustype.StatusPurpose:        "test",
			}}
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast URI of statusListCredential")
	})

	t.Run("test statusPurpose not exist", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = &verifiable.TypedID{
			Type: string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{
				statustype.StatusListIndex:      "1",
				statustype.StatusListCredential: 1,
			}}
		err = s.updateVC(cred, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusPurpose field not exist in vc status")
	})

	t.Run("test success", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		statusID, err := s.CreateStatusID(profileID)
		require.NoError(t, err)

		cred, err := verifiable.ParseCredential([]byte(universityDegreeCred),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cred.ID = credID
		cred.Status = statusID.VCStatus
		require.NoError(t, s.updateVC(cred, getTestSigner(), true))

		revocationListVC, err := s.GetStatusListVC(profileID, "1")
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusID.VCStatus.CustomFields[statustype.StatusListIndex].(string))
		require.NoError(t, err)

		credSubject, ok := revocationListVC.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
		bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
		require.NoError(t, err)
		bitSet, err := bitString.Get(revocationListIndex)
		require.NoError(t, err)
		require.True(t, bitSet)
	})

	t.Run("test error get csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(func(store *mockCSLStore) {
				store.findErr = errors.New("some error")
			}),
			VCStore:  newMockVCStore(),
			ListSize: 2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		err := s.updateVC(&verifiable.Credential{
			ID: credID,
			Status: &verifiable.TypedID{
				ID:   "test",
				Type: string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{
					statustype.StatusListCredential: "test",
					statustype.StatusListIndex:      "1",
					statustype.StatusPurpose:        "test",
				},
			},
		}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get csl from store")
	})

	t.Run("test error from sign status credential", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
			&mockKMS{crypto: &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}}, nil)

		s := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStore:        newMockVCStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})

		_, err := s.CreateStatusID(profileID)
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

func TestService_Resolve(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	// Assert
	credential, err := verifiable.ParseCredential(
		[]byte(sampleVCJWT),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	type fields struct {
		getVdr         func() vdr.Registry
		httpClient     httpClient
		documentLoader ld.DocumentLoader
	}
	type args struct {
		statusURL string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiable.Credential
		wantErr bool
	}{
		{
			name: "OK DID",
			fields: fields{
				getVdr: func() vdr.Registry {
					longformVDR, err := longform.New()
					require.NoError(t, err)

					return vdr2.New(vdr2.WithVDR(longformVDR))
				},
				httpClient:     http.DefaultClient,
				documentLoader: loader,
			},
			args: args{
				statusURL: didRelativeURL,
			},
			want:    credential,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:            tt.fields.getVdr(),
				httpClient:     tt.fields.httpClient,
				documentLoader: tt.fields.documentLoader,
				requestTokens: map[string]string{
					cslRequestTokenName: "abc",
				},
			}
			got, err := s.Resolve(tt.args.statusURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetStatusListVC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetStatusListVC() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func getTestSigner() *vc.Signer {
	return &vc.Signer{
		Format:           vcsverifiable.Ldp,
		DID:              "did:test:abc",
		SignatureType:    "Ed25519Signature2018",
		Creator:          "did:test:abc#key1",
		KMS:              &mockKMS{},
		VCStatusListType: vc.StatusList2021VCStatus,
	}
}

func getTestProfile() *profileapi.Issuer {
	return &profileapi.Issuer{
		ID:   profileID,
		Name: "testprofile",
		URL:  "https://localhost:8080",
		VCConfig: &profileapi.VCConfig{
			Format:           vcsverifiable.Ldp,
			SigningAlgorithm: "Ed25519Signature2018",
			Status: profileapi.StatusConfig{
				Type: vc.StatusList2021VCStatus,
			},
		},
		SigningDID: &profileapi.SigningDID{
			DID:     "did:test:abc",
			Creator: "did:test:abc#key1",
		},
	}
}

type mockCSLStore struct {
	createErr             error
	findErr               error
	getLatestListIDErr    error
	createLatestListIDErr error
	updateLatestListIDErr error
	latestListID          int
	s                     map[string]*cslstore.CSLWrapper
}

func newMockCSLStore(opts ...func(*mockCSLStore)) *mockCSLStore {
	s := &mockCSLStore{
		latestListID: -1,
		s:            map[string]*cslstore.CSLWrapper{},
	}
	for _, f := range opts {
		f(s)
	}
	return s
}

func (m *mockCSLStore) Upsert(cslWrapper *cslstore.CSLWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslWrapper.VC.ID] = cslWrapper
	return nil
}

func (m *mockCSLStore) Get(id string) (*cslstore.CSLWrapper, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}

	w, ok := m.s[id]
	if !ok {
		return nil, cslstore.ErrDataNotFound
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
		return -1, cslstore.ErrDataNotFound
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

	return signer.NewKMSSigner(&mockkms.KeyManager{}, m.crypto, creator, signatureType, nil)
}

func (m *mockKMS) SupportedKeyTypes() []kms.KeyType {
	return nil
}

func (m *mockKMS) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}

func (m *mockKMS) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return "", nil, nil
}
