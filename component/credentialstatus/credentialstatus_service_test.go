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
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
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
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

const (
	profileID = "testProfileID"
	credID    = "http://example.edu/credentials/1872"
)

func validateVCStatus(t *testing.T, s *Service, statusID *issuecredential.StatusListEntry, expectedListID credentialstatus.ListID) {
	t.Helper()

	require.Equal(t, string(vc.StatusList2021VCStatus), statusID.TypedID.Type)
	require.Equal(t, "revocation", statusID.TypedID.CustomFields[statustype.StatusPurpose].(string))

	existingStatusListVCID := statusID.TypedID.CustomFields[statustype.StatusListCredential].(string)

	chunks := strings.Split(existingStatusListVCID, "/")
	existingStatusVCListID := chunks[len(chunks)-1]
	require.Equal(t, string(expectedListID), existingStatusVCListID)

	statusListVC, err := s.GetStatusListVC(profileID, existingStatusVCListID)
	require.NoError(t, err)
	require.Equal(t, existingStatusListVCID, statusListVC.ID)
	require.Equal(t, "did:test:abc", statusListVC.Issuer.ID)
	require.Equal(t, vcutil.DefVCContext, statusListVC.Context[0])
	require.Equal(t, statustype.StatusList2021Context, statusListVC.Context[1])
	credSubject, ok := statusListVC.Subject.([]verifiable.Subject)
	require.True(t, ok)
	require.Equal(t, existingStatusListVCID+"#list", credSubject[0].ID)
	require.Equal(t, statustype.StatusList2021VCSubjectType, credSubject[0].CustomFields["type"].(string))
	require.Equal(t, "revocation", credSubject[0].CustomFields[statustype.StatusPurpose].(string))
	require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
	bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	require.NoError(t, err)

	revocationListIndex, err := strconv.Atoi(statusID.TypedID.CustomFields[statustype.StatusListIndex].(string))
	require.NoError(t, err)
	bitSet, err := bitString.Get(revocationListIndex)
	require.NoError(t, err)
	require.False(t, bitSet)
}

func TestCredentialStatusList_CreateStatusListEntry(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(5).Return(&mockKMS{}, nil)

		cslStore := newMockCSLStore()

		listID, err := cslStore.GetLatestListID()
		require.NoError(t, err)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       cslStore,
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusID, err := s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		statusID, err = s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		// List size equals 2, so after 2 issuances CSL encodedBitString is full and listID must be updated.
		updatedListID, err := cslStore.GetLatestListID()
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, listID)

		statusID, err = s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		statusID, err = s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		// List size equals 2, so after 4 issuances CSL encodedBitString is full and listID must be updated.
		updatedListIDSecond, err := cslStore.GetLatestListID()
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, updatedListIDSecond)
		require.NotEqual(t, listID, updatedListIDSecond)

		statusID, err = s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListIDSecond)
	})

	t.Run("test error get profile service", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, errors.New("some error"))

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get profile")
	})

	t.Run("test error get key manager", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(getTestProfile(), nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, errors.New("some error"))

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
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

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "unsupported VCStatusListType")
	})

	t.Run("test error from get latest list id from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(func(store *mockCSLStore) {
				store.getLatestListIDErr = errors.New("some error")
			}),
			VCStatusStore:  nil,
			ListSize:       1,
			KMSRegistry:    mockKMSRegistry,
			ProfileService: mockProfileSrv,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest list id to store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.createLatestListIDErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			ListSize:       1,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error create CSL wrapper URL", func(t *testing.T) {
		profile := getTestProfile()
		profile.URL = " https://example.com"
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(profile, nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			CSLStore:       newMockCSLStore(),
			KMSRegistry:    mockKMSRegistry,
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to create CSL wrapper URL")
	})

	t.Run("test error put typedID to store - list size too small", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore: &mockVCStore{
				s: map[string]*verifiable.TypedID{},
			},
			ListSize:       0,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "getUnusedIndex failed")
	})

	t.Run("test error put typedID to store - no available unused indexes", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		profile := getTestProfile()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(profile, nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)
		cslStore := newMockCSLStore()

		statusProcessor, err := statustype.GetVCStatusProcessor(vc.StatusList2021VCStatus)
		require.NoError(t, err)

		listID, err := cslStore.GetLatestListID()
		require.NoError(t, err)

		cslURL, err := cslStore.GetCSLURL(profile.URL, profile.ID, listID)
		require.NoError(t, err)

		csl, err := statusProcessor.CreateVC(cslURL, 2, &vc.Signer{DID: profile.SigningDID.DID})
		require.NoError(t, err)

		cslBytes, err := csl.MarshalJSON()
		require.NoError(t, err)

		require.NoError(t, cslStore.Upsert(&credentialstatus.CSLWrapper{
			VCByte:      cslBytes,
			UsedIndexes: []int{0, 1},
			VC:          csl,
		}))

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       cslStore,
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "getUnusedIndex failed")

	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.createErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       1,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store csl in store")
	})

	t.Run("test error update latest list id", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.updateLatestListIDErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       1,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store latest list ID in store")
	})

	t.Run("test error put typedID to store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore: &mockVCStore{
				putErr: errors.New("some error"),
				s:      map[string]*verifiable.TypedID{},
			},
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store credential status")
	})
}

func TestCredentialStatusList_GetStatusListVC(t *testing.T) {
	t.Run("test error get profile", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

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

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			CSLStore:       newMockCSLStore(),
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(profileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get CSL wrapper URL")
	})
	t.Run("test error getting csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(
				func(store *mockCSLStore) {
					store.findErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			ListSize:       2,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(profileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get revocationListVC from store")
	})
}

func TestCredentialStatusList_UpdateVCStatus(t *testing.T) {
	t.Run("UpdateVCStatus success", func(t *testing.T) {
		profile := getTestProfile()
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(profile, nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)

		err = vcStore.Put(profileID, credID, statusListEntry.TypedID)
		require.NoError(t, err)

		require.NoError(t, s.UpdateVCStatus(profileID, credID, "true", profile.VCConfig.Status.Type))

		listID, err := s.cslStore.GetLatestListID()
		require.NoError(t, err)

		statusListVC, err := s.GetStatusListVC(profileID, string(listID))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusListEntry.TypedID.CustomFields[statustype.StatusListIndex].(string))
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
		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, credID, "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get profile")
	})
	t.Run("UpdateVCStatus invalid vc status type error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, credID, "true", vc.RevocationList2020VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "not supported by current profile")
	})
	t.Run("UpdateVCStatus kmsRegistry.GetKeyManager error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, credID, "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get kms")
	})
	t.Run("UpdateVCStatus store.Get error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
		})
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, credID, "true", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "data not found")
	})
	t.Run("UpdateVCStatus ParseBool error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = vcStore.Put(profileID, credID, &verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)})
		require.NoError(t, err)

		err = s.UpdateVCStatus(profileID, credID, "undefined", vc.StatusList2021VCStatus)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid syntax")
	})
	t.Run("updateVCStatus not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(nil, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status not exist")
	})
	t.Run("updateVCStatus type not supported", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{Type: "noMatch"}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status noMatch not supported")
	})
	t.Run("updateVCStatus statusListIndex not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListIndex field not exist in vc status")
	})
	t.Run("updateVCStatus statusListCredential not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{
			Type:         string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{statustype.StatusListIndex: "1"},
		}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListCredential field not exist in vc status")
	})
	t.Run("updateVCStatus statusListCredential wrong value type", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{
			Type: string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{
				statustype.StatusListIndex:      "1",
				statustype.StatusListCredential: 1,
				statustype.StatusPurpose:        "test",
			}}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast URI of statusListCredential")
	})
	t.Run("updateVCStatus not exist", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{
			Type: string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{
				statustype.StatusListIndex:      "1",
				statustype.StatusListCredential: 1,
			}}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusPurpose field not exist in vc status")
	})
	t.Run("updateVCStatus success", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(profileID, credID)
		require.NoError(t, err)

		require.NoError(t, s.updateVCStatus(statusListEntry.TypedID, getTestSigner(), true))

		listID, err := s.cslStore.GetLatestListID()
		require.NoError(t, err)

		revocationListVC, err := s.GetStatusListVC(profileID, string(listID))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusListEntry.TypedID.CustomFields[statustype.StatusListIndex].(string))
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
	t.Run("updateVCStatus csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore: newMockCSLStore(func(store *mockCSLStore) {
				store.findErr = errors.New("some error")
			}),
			VCStatusStore: newMockVCStatusStore(),
			ListSize:      2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(&verifiable.TypedID{
			ID:   "test",
			Type: string(vc.StatusList2021VCStatus),
			CustomFields: map[string]interface{}{
				statustype.StatusListCredential: "test",
				statustype.StatusListIndex:      "1",
				statustype.StatusPurpose:        "test",
			},
		}, getTestSigner(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get csl from store")
	})
	t.Run("updateVCStatus sign status credential", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
			&mockKMS{crypto: &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLStore:       newMockCSLStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		_, err = s.CreateStatusListEntry(profileID, credID)
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
	latestListID          credentialstatus.ListID
	s                     map[string]*credentialstatus.CSLWrapper
}

func (m *mockCSLStore) GetCSLURL(issuerURL, issuerID string, listID credentialstatus.ListID) (string, error) {
	return url.JoinPath(issuerURL, "issuer/profiles", issuerID, "credentials/status", string(listID))
}

func newMockCSLStore(opts ...func(*mockCSLStore)) *mockCSLStore {
	s := &mockCSLStore{
		latestListID: "",
		s:            map[string]*credentialstatus.CSLWrapper{},
	}
	for _, f := range opts {
		f(s)
	}
	return s
}

func (m *mockCSLStore) Upsert(cslWrapper *credentialstatus.CSLWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslWrapper.VC.ID] = cslWrapper
	return nil
}

func (m *mockCSLStore) Get(id string) (*credentialstatus.CSLWrapper, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}

	w, ok := m.s[id]
	if !ok {
		return nil, credentialstatus.ErrDataNotFound
	}

	return w, nil
}
func (m *mockCSLStore) createLatestListID() error {
	if m.createLatestListIDErr != nil {
		return m.createLatestListIDErr
	}

	m.latestListID = getShortUUID()

	return nil
}

func getShortUUID() credentialstatus.ListID {
	return credentialstatus.ListID(strings.Split(uuid.NewString(), "-")[0])
}

func (m *mockCSLStore) UpdateLatestListID() error {
	if m.updateLatestListIDErr != nil {
		return m.updateLatestListIDErr
	}
	return m.createLatestListID()
}

func (m *mockCSLStore) GetLatestListID() (credentialstatus.ListID, error) {
	if m.getLatestListIDErr != nil {
		return "", m.getLatestListIDErr
	}

	if m.latestListID == "" {
		err := m.createLatestListID()
		if err != nil {
			return "", err
		}
	}

	return m.latestListID, nil
}

type mockVCStore struct {
	putErr error
	s      map[string]*verifiable.TypedID
}

func newMockVCStatusStore() *mockVCStore {
	return &mockVCStore{
		s: map[string]*verifiable.TypedID{},
	}
}

func (m *mockVCStore) Get(profileID, vcID string) (*verifiable.TypedID, error) {
	v, ok := m.s[fmt.Sprintf("%s_%s", profileID, vcID)]
	if !ok {
		return nil, errors.New("data not found")
	}

	return v, nil
}

func (m *mockVCStore) Put(profileID, vcID string, typedID *verifiable.TypedID) error {
	if m.putErr != nil {
		return m.putErr
	}

	m.s[fmt.Sprintf("%s_%s", profileID, vcID)] = typedID
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

func TestService_getUnusedIndex(t *testing.T) {
	type fields struct {
		listSize int
	}
	type args struct {
		usedIndexes []int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantOK  func(index int) bool
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				listSize: 1,
			},
			args: args{
				usedIndexes: []int{},
			},
			wantOK: func(index int) bool {
				return index == 0
			},
			wantErr: false,
		},
		{
			name: "OK list size 3",
			fields: fields{
				listSize: 3,
			},
			args: args{
				usedIndexes: []int{2},
			},
			wantOK: func(index int) bool {
				return index == 1 || index == 0
			},
			wantErr: false,
		},
		{
			name: "OK list size 3",
			fields: fields{
				listSize: 3,
			},
			args: args{
				usedIndexes: []int{0, 2},
			},
			wantOK: func(index int) bool {
				return index == 1
			},
			wantErr: false,
		},
		{
			name: "Error list size 3",
			fields: fields{
				listSize: 3,
			},
			args: args{
				usedIndexes: []int{0, 1, 2},
			},
			wantOK: func(index int) bool {
				return index == -1
			},
			wantErr: true,
		},
		{
			name: "Error list size is too small",
			fields: fields{
				listSize: 0,
			},
			args: args{
				usedIndexes: []int{},
			},
			wantOK: func(index int) bool {
				return index == -1
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				listSize: tt.fields.listSize,
			}
			got, err := s.getUnusedIndex(tt.args.usedIndexes)
			if (err != nil) != tt.wantErr {
				t.Errorf("getUnusedIndex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantOK(got) {
				t.Errorf("getUnusedIndex() got invalid value %v", got)
			}
		})
	}
}
