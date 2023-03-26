/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"context"
	_ "embed"
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
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus/eventhandler"
)

const (
	profileID         = "testProfileID"
	externalProfileID = "externalID"
	credID            = "http://example.edu/credentials/1872"
	eventTopic        = "testEventTopic"
)

func validateVCStatus(t *testing.T, s *Service, statusID *credentialstatus.StatusListEntry, expectedListID credentialstatus.ListID) {
	t.Helper()

	require.Equal(t, string(vc.StatusList2021VCStatus), statusID.TypedID.Type)
	require.Equal(t, "revocation", statusID.TypedID.CustomFields[statustype.StatusPurpose].(string))

	existingStatusListVCID := statusID.TypedID.CustomFields[statustype.StatusListCredential].(string)

	chunks := strings.Split(existingStatusListVCID, "/")
	existingStatusVCListID := chunks[len(chunks)-1]
	require.Equal(t, string(expectedListID), existingStatusVCListID)

	statusListVC, err := s.GetStatusListVC(context.Background(), externalProfileID, existingStatusVCListID)
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
		ctx := context.Background()

		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		listID, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLIndexStore:  cslIndexStore,
			CSLVCStore:     cslVCStore,
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ExternalURL:    "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusID, err := s.CreateStatusListEntry(ctx, profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		// List size equals 2, so after 2 issuances CSL encodedBitString is full and listID must be updated.
		updatedListID, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, listID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		// List size equals 2, so after 4 issuances CSL encodedBitString is full and listID must be updated.
		updatedListIDSecond, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, updatedListIDSecond)
		require.NotEqual(t, listID, updatedListIDSecond)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, credID)
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get KMS")
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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
			CSLIndexStore: newMockCSLIndexStore(func(store *mockCSLIndexStore) {
				store.getLatestListIDErr = errors.New("some error")
			}),
			CSLVCStore:     newMockCSLVCStore(),
			VCStatusStore:  nil,
			ListSize:       1,
			KMSRegistry:    mockKMSRegistry,
			ProfileService: mockProfileSrv,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error create CSL wrapper URL", func(t *testing.T) {
		profile := getTestProfile()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).Times(1).Return(profile, nil)

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			CSLIndexStore:  newMockCSLIndexStore(),
			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.getCSLErr = errors.New("some error")
				}),
			KMSRegistry: mockKMSRegistry,
			ExternalURL: "https://example.com",
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(context.Background(), externalProfileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to create CSL wrapper URL")
	})

	t.Run("test error from CSL VC store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)
		ctx := context.Background()

		cslIndexStore := newMockCSLIndexStore()

		_, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLIndexStore:  cslIndexStore,
			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.createErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ExternalURL:    "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(ctx, profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store CSL VC in store: some error")
	})

	t.Run("test error put typedID to store - list size too small", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLIndexStore:  newMockCSLIndexStore(),
			CSLVCStore:     newMockCSLVCStore(),
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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
		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		statusProcessor, err := statustype.GetVCStatusProcessor(vc.StatusList2021VCStatus)
		require.NoError(t, err)

		listID, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		cslURL, err := cslVCStore.GetCSLURL("https://localhost:8080", profile.GroupID, listID)

		require.NoError(t, err)

		csl, err := statusProcessor.CreateVC(cslURL, 2, &vc.Signer{DID: profile.SigningDID.DID})
		require.NoError(t, err)

		cslBytes, err := csl.MarshalJSON()
		require.NoError(t, err)

		require.NoError(t, cslIndexStore.Upsert(context.Background(), cslURL, &credentialstatus.CSLIndexWrapper{
			UsedIndexes: []int{0, 1},
		}))

		require.NoError(t, cslVCStore.Upsert(context.Background(), cslURL, &credentialstatus.CSLVCWrapper{
			VCByte: cslBytes,
		}))

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslVCStore,
			CSLIndexStore:  cslIndexStore,
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ExternalURL:    "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store CSL Wrapper: some error")
	})

	t.Run("test error update latest list id", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
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
			CSLIndexStore:  newMockCSLIndexStore(),
			CSLVCStore:     newMockCSLVCStore(),
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

		status, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store credential status")
	})
}

func TestCredentialStatusList_GetStatusListVC(t *testing.T) {
	t.Run("test error get status list vc url", func(t *testing.T) {
		profile := getTestProfile()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(profile, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			ExternalURL:    " https://example.com",
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(context.Background(), externalProfileID, "1")
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
			CSLIndexStore:  newMockCSLIndexStore(),
			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.findErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			ListSize:       2,
			Crypto: vccrypto.New(&vdrmock.MockVDRegistry{},
				loader),
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(context.Background(), externalProfileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "failed to get CSL from store")
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
		cslVCStore := newMockCSLVCStore()
		cslIndexStore := newMockCSLIndexStore()
		crypto := vccrypto.New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)
		ctx := context.Background()

		mockEventPublisher := &mockedEventPublisher{
			eventHandler: eventhandler.New(&eventhandler.Config{
				CSLVCStore:     cslVCStore,
				CSLIndexStore:  cslIndexStore,
				ProfileService: mockProfileSrv,
				KMSRegistry:    mockKMSRegistry,
				Crypto:         crypto,
				DocumentLoader: loader,
			}),
		}

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslVCStore,
			CSLIndexStore:  cslIndexStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			ListSize:       2,
			EventTopic:     eventTopic,
			EventPublisher: mockEventPublisher,
			Crypto:         crypto,
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(ctx, profileID, credID)
		require.NoError(t, err)

		err = vcStore.Put(ctx, profileID, credID, statusListEntry.TypedID)
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "true",
			StatusType:    profile.VCConfig.Status.Type,
		}

		require.NoError(t, s.UpdateVCStatus(ctx, params))

		listID, err := s.cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)

		statusListVC, err := s.GetStatusListVC(ctx, externalProfileID, string(listID))
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

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "true",
			StatusType:    vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
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

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "true",
			StatusType:    vc.RevocationList2020VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "vc status list version \"RevocationList2020Status\" is not supported by current profile")
	})
	t.Run("UpdateVCStatus store.Get error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
		})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "true",
			StatusType:    vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "vcStatusStore.Get failed")
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
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = vcStore.Put(
			context.Background(), profileID, credID, &verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "undefined",
			StatusType:    vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "strconv.ParseBool failed")
	})
	t.Run("UpdateVCStatus updateVCStatus error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = vcStore.Put(
			context.Background(), profileID, credID, &verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:     profileID,
			CredentialID:  credID,
			DesiredStatus: "true",
			StatusType:    vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "updateVCStatus failed")
	})
	t.Run("updateVCStatus - ValidateStatus - not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			nil,
			profileID, vc.StatusList2021VCStatus, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status not exist")
	})
	t.Run("updateVCStatus - statustype.GetVCStatusProcessor error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			nil,
			profileID,
			"unsupported",
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get VC status processor failed")
	})
	t.Run("updateVCStatus - ValidateStatus - type not supported", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{Type: "noMatch"},
			profileID, vc.StatusList2021VCStatus, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status noMatch not supported")
	})
	t.Run("updateVCStatus - ValidateStatus - statusListIndex not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)},
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListIndex field not exist in vc status")
	})
	t.Run("updateVCStatus - ValidateStatus - statusListCredential not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{
				Type:         string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{statustype.StatusListIndex: "1"},
			},
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusListCredential field not exist in vc status")
	})
	t.Run("updateVCStatus - ValidateStatus - statusPurpose field not exist", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{
				Type: string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{
					statustype.StatusListIndex:      "1",
					statustype.StatusListCredential: 1,
				}},
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "statusPurpose field not exist in vc status")
	})
	t.Run("updateVCStatus - GetStatusVCURI - wrong VC URI", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ListSize:       2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{
				Type: string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{
					statustype.StatusListIndex:      "1",
					statustype.StatusListCredential: 1,
					statustype.StatusPurpose:        "test",
				}},
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast URI of statusListCredential")
	})
	t.Run("updateVCStatus - get CSL from store error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore: newMockCSLVCStore(func(store *mockCSLVCStore) {
				store.findErr = errors.New("some error")
			}),
			VCStatusStore: newMockVCStatusStore(),
			ListSize:      2,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{
				ID:   "test",
				Type: string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{
					statustype.StatusListCredential: "test",
					statustype.StatusListIndex:      "1",
					statustype.StatusPurpose:        "test",
				},
			},
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get CSL from store")
	})
	t.Run("updateVCStatus unable to publish event", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)
		mockEventPublisher := NewMockEventPublisher(gomock.NewController(t))
		mockEventPublisher.EXPECT().Publish(gomock.Any(), eventTopic, gomock.Any()).Times(1).Return(errors.New("some error"))

		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			CSLIndexStore:  newMockCSLIndexStore(),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			EventPublisher: mockEventPublisher,
			EventTopic:     eventTopic,
			Crypto: vccrypto.New(
				&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.NoError(t, err)
		err = s.updateVCStatus(
			context.Background(),
			statusListEntry.TypedID,
			profileID,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to publish event")
	})
	t.Run("updateVCStatus success", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(gomock.Any()).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&mockKMS{}, nil)
		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()
		loader := testutil.DocumentLoader(t)
		crypto := vccrypto.New(
			&vdrmock.MockVDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)

		mockEventPublisher := &mockedEventPublisher{
			eventHandler: eventhandler.New(&eventhandler.Config{
				CSLVCStore:     cslVCStore,
				CSLIndexStore:  cslIndexStore,
				ProfileService: mockProfileSrv,
				KMSRegistry:    mockKMSRegistry,
				Crypto:         crypto,
				DocumentLoader: loader,
			}),
		}

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslVCStore,
			CSLIndexStore:  cslIndexStore,
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ListSize:       2,
			EventTopic:     eventTopic,
			EventPublisher: mockEventPublisher,
			Crypto:         crypto,
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(context.Background(), profileID, credID)
		require.NoError(t, err)

		require.NoError(t, s.updateVCStatus(
			context.Background(),
			statusListEntry.TypedID,
			profileID,
			vc.StatusList2021VCStatus,
			true))

		listID, err := s.cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		revocationListVC, err := s.GetStatusListVC(context.Background(), externalProfileID, string(listID))
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
			got, err := s.Resolve(context.Background(), tt.args.statusURL)
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

type eventHandler interface {
	HandleEvent(ctx context.Context, event *spi.Event) error
}

type mockedEventPublisher struct {
	eventHandler eventHandler
}

func (ep *mockedEventPublisher) Publish(ctx context.Context, topic string, messages ...*spi.Event) error {
	var err error

	for _, event := range messages {
		err = ep.eventHandler.HandleEvent(ctx, event)
		if err != nil {
			return err
		}
	}

	return err
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
		ID:      profileID,
		Name:    "testprofile",
		GroupID: "externalID",
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

type mockCSLIndexStore struct {
	createErr             error
	findErr               error
	getLatestListIDErr    error
	createLatestListIDErr error
	updateLatestListIDErr error
	latestListID          credentialstatus.ListID
	s                     map[string]*credentialstatus.CSLIndexWrapper
}

func newMockCSLIndexStore(opts ...func(*mockCSLIndexStore)) *mockCSLIndexStore {
	s := &mockCSLIndexStore{
		latestListID: "",
		s:            map[string]*credentialstatus.CSLIndexWrapper{},
	}
	for _, f := range opts {
		f(s)
	}
	return s
}

func (m *mockCSLIndexStore) Upsert(ctx context.Context, cslURL string, cslWrapper *credentialstatus.CSLIndexWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslURL] = cslWrapper

	return nil
}

func (m *mockCSLIndexStore) Get(ctx context.Context, cslURL string) (*credentialstatus.CSLIndexWrapper, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}

	w, ok := m.s[cslURL]
	if !ok {
		return nil, credentialstatus.ErrDataNotFound
	}

	return w, nil
}
func (m *mockCSLIndexStore) createLatestListID() error {
	if m.createLatestListIDErr != nil {
		return m.createLatestListIDErr
	}

	m.latestListID = credentialstatus.ListID(uuid.NewString())

	return nil
}

func (m *mockCSLIndexStore) UpdateLatestListID(ctx context.Context) error {
	if m.updateLatestListIDErr != nil {
		return m.updateLatestListIDErr
	}
	return m.createLatestListID()
}

func (m *mockCSLIndexStore) GetLatestListID(ctx context.Context) (credentialstatus.ListID, error) {
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

type mockCSLVCStore struct {
	createErr error
	getCSLErr error
	findErr   error
	s         map[string]*credentialstatus.CSLVCWrapper
}

func newMockCSLVCStore(opts ...func(*mockCSLVCStore)) *mockCSLVCStore {
	s := &mockCSLVCStore{
		s: map[string]*credentialstatus.CSLVCWrapper{},
	}
	for _, f := range opts {
		f(s)
	}
	return s
}

func (m *mockCSLVCStore) GetCSLURL(issuerURL, issuerID string, listID credentialstatus.ListID) (string, error) {
	if m.getCSLErr != nil {
		return "", m.getCSLErr
	}

	return url.JoinPath(issuerURL, "issuer/profiles", issuerID, "credentials/status", string(listID))
}

func (m *mockCSLVCStore) Upsert(ctx context.Context, cslURL string, cslWrapper *credentialstatus.CSLVCWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslURL] = cslWrapper

	return nil
}

func (m *mockCSLVCStore) Get(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}

	w, ok := m.s[cslURL]
	if !ok {
		return nil, credentialstatus.ErrDataNotFound
	}

	return w, nil
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

func (m *mockVCStore) Get(ctx context.Context, profileID, vcID string) (*verifiable.TypedID, error) {
	v, ok := m.s[fmt.Sprintf("%s_%s", profileID, vcID)]
	if !ok {
		return nil, errors.New("data not found")
	}

	return v, nil
}

func (m *mockVCStore) Put(ctx context.Context, profileID, vcID string, typedID *verifiable.TypedID) error {
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
