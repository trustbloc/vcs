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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/spi/kms"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"

	"github.com/trustbloc/vcs/internal/mock/vcskms"

	timeutil "github.com/trustbloc/did-go/doc/util/time"
	vdr2 "github.com/trustbloc/did-go/vdr"
	vdr "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/credentialstatus/internal/testutil"
	"github.com/trustbloc/vcs/pkg/cslmanager"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus/eventhandler"
)

const (
	profileID         = "testProfileID"
	profileVersion    = "testProfileVersion"
	externalProfileID = "externalID"
	credID            = "http://example.edu/credentials/1872"
	eventTopic        = "testEventTopic"
)

func validateVCStatus(
	t *testing.T, s *Service, statusID *credentialstatus.StatusListEntry, expectedListID credentialstatus.ListID) {
	t.Helper()

	require.Equal(t, string(vc.StatusList2021VCStatus), statusID.TypedID.Type)
	require.Equal(t, "revocation", statusID.TypedID.CustomFields[statustype.StatusPurpose].(string))

	existingStatusListVCID, ok := statusID.TypedID.CustomFields[statustype.StatusListCredential].(string)
	require.True(t, ok)

	chunks := strings.Split(existingStatusListVCID, "/")
	existingStatusVCListID := chunks[len(chunks)-1]
	require.Equal(t, string(expectedListID), existingStatusVCListID)

	statusListVC, err := s.GetStatusListVC(context.Background(), externalProfileID, existingStatusVCListID)
	require.NoError(t, err)

	statusListVCC := statusListVC.Contents()

	require.Equal(t, existingStatusListVCID, statusListVCC.ID)
	require.Equal(t, "did:test:abc", statusListVCC.Issuer.ID)
	require.Equal(t, vcutil.DefVCContext, statusListVCC.Context[0])
	require.Equal(t, statustype.StatusList2021Context, statusListVCC.Context[1])
	credSubject := statusListVCC.Subject
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
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(5).Return(&vcskms.MockKMS{}, nil)
		ctx := context.Background()

		cslVCStore := newMockCSLVCStore()

		cslIndexStore := newMockCSLIndexStore()

		listID, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)

		vcStatusStore := newMockVCStatusStore()

		cslMgr, err := cslmanager.New(
			&cslmanager.Config{
				CSLVCStore:    cslVCStore,
				CSLIndexStore: cslIndexStore,
				VCStatusStore: vcStatusStore,
				ListSize:      2,
				KMSRegistry:   mockKMSRegistry,
				ExternalURL:   "https://localhost:8080",
				Crypto: vccrypto.New(
					&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
			})
		require.NoError(t, err)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLManager:     cslMgr,
			CSLVCStore:     cslVCStore,
			VCStatusStore:  vcStatusStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			ExternalURL:    "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusID, err := s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, listID)

		// List size equals 2, so after 2 issuances CSL encodedBitString is full and listID must be updated.
		updatedListID, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, listID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListID)

		// List size equals 2, so after 4 issuances CSL encodedBitString is full and listID must be updated.
		updatedListIDSecond, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, updatedListIDSecond)
		require.NotEqual(t, listID, updatedListIDSecond)

		statusID, err = s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)
		validateVCStatus(t, s, statusID, updatedListIDSecond)
	})

	t.Run("test error get profile service", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(nil, errors.New("some error"))

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		status, err := s.CreateStatusListEntry(context.Background(), profileID, profileVersion, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "get profile")
	})
}

func TestCredentialStatusList_GetStatusListVC(t *testing.T) {
	t.Run("test error get status list vc url", func(t *testing.T) {
		profile := getTestProfile()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(profile, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			CSLVCStore:     newMockCSLVCStore(),
			ExternalURL:    " https://example.com",
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(context.Background(), externalProfileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "get CSL wrapper URL")
	})
	t.Run("test error getting csl from store", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)

		s, err := New(&Config{
			DocumentLoader: loader,

			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.findErr = errors.New("some error")
				}),
			VCStatusStore:  newMockVCStatusStore(),
			ProfileService: mockProfileSrv,
			Crypto: vccrypto.New(&vdrmock.VDRegistry{},
				loader),
		})
		require.NoError(t, err)

		csl, err := s.GetStatusListVC(context.Background(), externalProfileID, "1")
		require.Error(t, err)
		require.Nil(t, csl)
		require.Contains(t, err.Error(), "get CSL from store")
	})
}

func TestCredentialStatusList_UpdateVCStatus(t *testing.T) {
	t.Run("UpdateVCStatus success", func(t *testing.T) {
		profile := getTestProfile()
		loader := testutil.DocumentLoader(t)
		vcStatusStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(profile, nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
		cslVCStore := newMockCSLVCStore()
		cslIndexStore := newMockCSLIndexStore()
		crypto := vccrypto.New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)
		ctx := context.Background()

		cslMgr, err := cslmanager.New(
			&cslmanager.Config{
				CSLVCStore:    cslVCStore,
				CSLIndexStore: cslIndexStore,
				VCStatusStore: vcStatusStore,
				ListSize:      2,
				KMSRegistry:   mockKMSRegistry,
				Crypto: vccrypto.New(
					&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
			})
		require.NoError(t, err)

		mockEventPublisher := &mockedEventPublisher{
			eventHandler: eventhandler.New(&eventhandler.Config{
				CSLVCStore:     cslVCStore,
				ProfileService: mockProfileSrv,
				KMSRegistry:    mockKMSRegistry,
				Crypto:         crypto,
				DocumentLoader: loader,
			}),
		}

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslVCStore,
			CSLManager:     cslMgr,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStatusStore,
			EventTopic:     eventTopic,
			EventPublisher: mockEventPublisher,
			Crypto:         crypto,
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(ctx, profileID, profileVersion, credID)
		require.NoError(t, err)

		err = vcStatusStore.Put(ctx, profileID, profileVersion, credID, statusListEntry.TypedID)
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "true",
			StatusType:     profile.VCConfig.Status.Type,
		}

		require.NoError(t, s.UpdateVCStatus(ctx, params))

		listID, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)

		statusListVC, err := s.GetStatusListVC(ctx, externalProfileID, string(listID))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusListEntry.TypedID.CustomFields[statustype.StatusListIndex].(string))
		require.NoError(t, err)

		credSubject := statusListVC.Contents().Subject
		require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
		bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
		require.NoError(t, err)
		bitSet, err := bitString.Get(revocationListIndex)
		require.NoError(t, err)
		require.True(t, bitSet)
	})
	t.Run("UpdateVCStatus profileService.GetProfile error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(nil, errors.New("some error"))
		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "true",
			StatusType:     vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "get profile")
	})
	t.Run("UpdateVCStatus invalid vc status type error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		s, err := New(&Config{
			ProfileService: mockProfileSrv,
		})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "true",
			StatusType:     vc.RevocationList2020VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err,
			"vc status list version \"RevocationList2020Status\" is not supported by current profile")
	})
	t.Run("UpdateVCStatus store.Get error", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			CSLVCStore:     newMockCSLVCStore(),
			VCStatusStore:  newMockVCStatusStore(),
		})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "true",
			StatusType:     vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "vcStatusStore.Get failed")
	})
	t.Run("UpdateVCStatus ParseBool error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),

			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = vcStore.Put(
			context.Background(), profileID, profileVersion, credID, &verifiable.TypedID{
				Type: string(vc.StatusList2021VCStatus)})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "undefined",
			StatusType:     vc.StatusList2021VCStatus,
		}

		err = s.UpdateVCStatus(context.Background(), params)
		require.Error(t, err)
		require.ErrorContains(t, err, "strconv.ParseBool failed")
	})
	t.Run("UpdateVCStatus updateVCStatus error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		vcStore := newMockVCStatusStore()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			VCStatusStore:  vcStore,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = vcStore.Put(
			context.Background(), profileID, profileVersion, credID,
			&verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)})
		require.NoError(t, err)

		params := credentialstatus.UpdateVCStatusParams{
			ProfileID:      profileID,
			ProfileVersion: profileVersion,
			CredentialID:   credID,
			DesiredStatus:  "true",
			StatusType:     vc.StatusList2021VCStatus,
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

			VCStatusStore: newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			nil,
			profileID, profileVersion,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status not exist")
	})
	t.Run("updateVCStatus - statustype.GetVCStatusProcessor error", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),

			VCStatusStore: newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			nil,
			profileID, profileVersion,
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

			VCStatusStore: newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{Type: "noMatch"},
			profileID, profileVersion,
			vc.StatusList2021VCStatus, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc status noMatch not supported")
	})
	t.Run("updateVCStatus - ValidateStatus - statusListIndex not exists", func(t *testing.T) {
		loader := testutil.DocumentLoader(t)
		s, err := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     newMockCSLVCStore(),

			VCStatusStore: newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{Type: string(vc.StatusList2021VCStatus)},
			profileID, profileVersion,
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

			VCStatusStore: newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			&verifiable.TypedID{
				Type:         string(vc.StatusList2021VCStatus),
				CustomFields: map[string]interface{}{statustype.StatusListIndex: "1"},
			},
			profileID, profileVersion,
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
			VCStatusStore:  newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
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
			profileID, profileVersion,
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
			VCStatusStore:  newMockVCStatusStore(),
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
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
			profileID, profileVersion,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast URI of statusListCredential")
	})
	t.Run("updateVCStatus unable to publish event", func(t *testing.T) {
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(getTestProfile(), nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
		mockEventPublisher := NewMockEventPublisher(gomock.NewController(t))
		mockEventPublisher.EXPECT().Publish(gomock.Any(), eventTopic, gomock.Any()).Times(1).Return(errors.New("some error"))

		cslVCStore := newMockCSLVCStore()
		cslIndexStore := newMockCSLIndexStore()
		vcStatusStore := newMockVCStatusStore()
		loader := testutil.DocumentLoader(t)

		cslMgr, err := cslmanager.New(
			&cslmanager.Config{
				CSLVCStore:    cslVCStore,
				CSLIndexStore: cslIndexStore,
				VCStatusStore: vcStatusStore,
				ListSize:      2,
				KMSRegistry:   mockKMSRegistry,
				Crypto: vccrypto.New(
					&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
			})
		require.NoError(t, err)

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLManager:     cslMgr,
			CSLVCStore:     cslVCStore,
			VCStatusStore:  vcStatusStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			EventPublisher: mockEventPublisher,
			EventTopic:     eventTopic,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(context.Background(), profileID, profileVersion, credID)
		require.NoError(t, err)

		err = s.updateVCStatus(
			context.Background(),
			statusListEntry.TypedID,
			profileID, profileVersion,
			vc.StatusList2021VCStatus,
			true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to publish event")
	})
	t.Run("updateVCStatus success", func(t *testing.T) {
		profile := getTestProfile()
		mockProfileSrv := NewMockProfileService(gomock.NewController(t))
		mockProfileSrv.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(profile, nil)
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()
		loader := testutil.DocumentLoader(t)
		crypto := vccrypto.New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)

		vcStatusStore := newMockVCStatusStore()

		cslMgr, err := cslmanager.New(
			&cslmanager.Config{
				CSLVCStore:    cslVCStore,
				CSLIndexStore: cslIndexStore,
				VCStatusStore: vcStatusStore,
				ListSize:      2,
				KMSRegistry:   mockKMSRegistry,
				Crypto: vccrypto.New(
					&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader),
			})

		require.NoError(t, err)

		mockEventPublisher := &mockedEventPublisher{
			eventHandler: eventhandler.New(&eventhandler.Config{
				CSLVCStore:     cslVCStore,
				ProfileService: mockProfileSrv,
				KMSRegistry:    mockKMSRegistry,
				Crypto:         crypto,
				DocumentLoader: loader,
			}),
		}

		s, err := New(&Config{
			DocumentLoader: loader,
			CSLManager:     cslMgr,
			CSLVCStore:     cslVCStore,
			VCStatusStore:  vcStatusStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			EventTopic:     eventTopic,
			EventPublisher: mockEventPublisher,
			Crypto:         crypto,
		})
		require.NoError(t, err)

		statusListEntry, err := s.CreateStatusListEntry(context.Background(), profile.ID, profile.Version, credID)
		require.NoError(t, err)

		require.NoError(t, s.updateVCStatus(
			context.Background(),
			statusListEntry.TypedID,
			profile.ID,
			profile.Version,
			vc.StatusList2021VCStatus,
			true))

		listID, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		revocationListVC, err := s.GetStatusListVC(context.Background(), externalProfileID, string(listID))
		require.NoError(t, err)
		revocationListIndex, err := strconv.Atoi(statusListEntry.TypedID.CustomFields[statustype.StatusListIndex].(string))
		require.NoError(t, err)

		credSubject := revocationListVC.Contents().Subject
		require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
		bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
		require.NoError(t, err)
		bitSet, err := bitString.Get(revocationListIndex)
		require.NoError(t, err)
		require.True(t, bitSet)
	})
}

func TestService_Resolve(t *testing.T) {
	t.Skip("Check issue with resolving did:ion")
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

func (ep *mockedEventPublisher) Publish(ctx context.Context, _ string, messages ...*spi.Event) error {
	var err error

	for _, event := range messages {
		if err = validateEvent(event); err != nil {
			return err
		}

		err = ep.eventHandler.HandleEvent(ctx, event)
		if err != nil {
			return err
		}
	}

	return err
}

func validateEvent(e *spi.Event) error {
	unexpectedFieldFmt := "unexpected %s field"
	if e.SpecVersion != "1.0" {
		return fmt.Errorf(unexpectedFieldFmt, "SpecVersion")
	}

	if c := strings.Split(e.ID, "-"); len(c) != 5 {
		return fmt.Errorf(unexpectedFieldFmt, "ID")
	}

	if e.Source != "source://vcs/status" {
		return fmt.Errorf(unexpectedFieldFmt, "Source")
	}

	if e.Time.IsZero() {
		return fmt.Errorf(unexpectedFieldFmt, "Time")
	}

	if e.DataContentType != "application/json" {
		return fmt.Errorf(unexpectedFieldFmt, "DataContentType")
	}

	if len(e.Data.(map[string]interface{})) == 0 {
		return fmt.Errorf(unexpectedFieldFmt, "Data")
	}

	if e.TransactionID != "" {
		return fmt.Errorf(unexpectedFieldFmt, "TransactionID")
	}

	if e.Subject != "" {
		return fmt.Errorf(unexpectedFieldFmt, "Subject")
	}

	if e.Tracing != "" {
		return fmt.Errorf(unexpectedFieldFmt, "Tracing")
	}

	return nil
}

func getTestProfile() *profileapi.Issuer {
	return &profileapi.Issuer{
		ID:      profileID,
		Version: profileVersion,
		Name:    "testprofile",
		GroupID: "externalID",
		VCConfig: &profileapi.VCConfig{
			Format:           vcsverifiable.Ldp,
			SigningAlgorithm: "Ed25519Signature2018",
			KeyType:          kms.ED25519Type,
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

func newMockCSLIndexStore() *mockCSLIndexStore {
	return &mockCSLIndexStore{
		latestListID: "",
		s:            map[string]*credentialstatus.CSLIndexWrapper{},
	}
}

func (m *mockCSLIndexStore) Upsert(
	_ context.Context, cslURL string, cslWrapper *credentialstatus.CSLIndexWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslURL] = cslWrapper

	return nil
}

func (m *mockCSLIndexStore) Get(_ context.Context, cslURL string) (*credentialstatus.CSLIndexWrapper, error) {
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

func (m *mockCSLIndexStore) UpdateLatestListID(_ context.Context, _ credentialstatus.ListID) error {
	if m.updateLatestListIDErr != nil {
		return m.updateLatestListIDErr
	}
	return m.createLatestListID()
}

func (m *mockCSLIndexStore) GetLatestListID(_ context.Context) (credentialstatus.ListID, error) {
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

func (m *mockCSLVCStore) Upsert(_ context.Context, cslURL string, cslWrapper *credentialstatus.CSLVCWrapper) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.s[cslURL] = cslWrapper

	return nil
}

func (m *mockCSLVCStore) Get(_ context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
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

func (m *mockVCStore) Get(_ context.Context, profileID, profileVersion, vcID string) (*verifiable.TypedID, error) {
	v, ok := m.s[fmt.Sprintf("%s_%s_%s", profileID, profileVersion, vcID)]
	if !ok {
		return nil, errors.New("data not found")
	}

	return v, nil
}

func (m *mockVCStore) Put(
	_ context.Context,
	profileID, profileVersion, credentialID string,
	typedID *verifiable.TypedID,
) error {
	if m.putErr != nil {
		return m.putErr
	}

	m.s[fmt.Sprintf("%s_%s_%s", profileID, profileVersion, credentialID)] = typedID

	return nil
}

func TestService_StoreIssuedCredentialMetadata(t *testing.T) {
	mockStore := NewMockCredentialIssuanceHistoryStore(gomock.NewController(t))
	txID := uuid.NewString()
	ctx := context.Background()
	expectedMetadata := &credentialstatus.CredentialMetadata{
		CredentialID:   "credentialID",
		Issuer:         "testIssuer",
		CredentialType: []string{"verifiableCredential"},
		TransactionID:  txID,
		IssuanceDate:   timeutil.NewTime(time.Now()),
		ExpirationDate: nil,
	}

	t.Run("Success", func(t *testing.T) {
		mockStore.EXPECT().Put(ctx, profileID, profileVersion, expectedMetadata).Times(1).Return(nil)

		s := &Service{credentialIssuanceHistoryStore: mockStore}

		err := s.StoreIssuedCredentialMetadata(ctx, profileID, profileVersion, expectedMetadata)
		require.NoError(t, err)
	})

	t.Run("Error credentialIssuanceHistoryStore", func(t *testing.T) {
		mockStore.EXPECT().Put(ctx, profileID, profileVersion, expectedMetadata).
			Times(1).Return(errors.New("some error"))

		s := &Service{credentialIssuanceHistoryStore: mockStore}

		err := s.StoreIssuedCredentialMetadata(ctx, profileID, profileVersion, expectedMetadata)
		require.Error(t, err)
	})
}
