/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vcs/internal/mock/vcskms"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/doc/did"
	model "github.com/trustbloc/did-go/doc/did/endpoint"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	testProfileID      = "testtestProfile"
	testProfileVersion = "v1.0"
	credID             = "http://example.edu/credentials/1872"
)

const (
	serviceTypeIdentityHub = "IdentityHub"
)

func TestCredentialStatusList_CreateCSLEntry(t *testing.T) {
	testProfile := getTestProfile()
	loader := testutil.DocumentLoader(t)

	t.Run("test success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKMSRegistry := NewMockKMSRegistry(ctrl)
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(5).Return(&vcskms.MockKMS{}, nil)
		ctx := context.Background()

		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		mockVCStatusStore := NewMockVCStatusStore(ctrl)
		mockVCStatusStore.EXPECT().
			Put(gomock.Any(), testProfileID, testProfileVersion, credID, gomock.Any()).
			Times(5).Return(nil)

		listID, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		s, err := New(&Config{
			CSLIndexStore: cslIndexStore,
			CSLVCStore:    cslVCStore,
			VCStatusStore: mockVCStatusStore,
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			ExternalURL:   "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		statusID, err := s.CreateCSLEntry(ctx, testProfile, credID)
		require.NoError(t, err)
		validateVCStatus(t, cslVCStore, statusID, listID)

		statusID, err = s.CreateCSLEntry(ctx, testProfile, credID)
		require.NoError(t, err)
		validateVCStatus(t, cslVCStore, statusID, listID)

		// List size equals 2, so after 2 issuances CSL encodedBitString is full and listID must be updated.
		updatedListID, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, listID)

		statusID, err = s.CreateCSLEntry(ctx, testProfile, credID)
		require.NoError(t, err)
		validateVCStatus(t, cslVCStore, statusID, updatedListID)

		statusID, err = s.CreateCSLEntry(ctx, testProfile, credID)
		require.NoError(t, err)
		validateVCStatus(t, cslVCStore, statusID, updatedListID)

		// List size equals 2, so after 4 issuances CSL encodedBitString is full and listID must be updated.
		updatedListIDSecond, err := cslIndexStore.GetLatestListID(ctx)
		require.NoError(t, err)
		require.NotEqual(t, updatedListID, updatedListIDSecond)
		require.NotEqual(t, listID, updatedListIDSecond)

		statusID, err = s.CreateCSLEntry(ctx, testProfile, credID)
		require.NoError(t, err)
		validateVCStatus(t, cslVCStore, statusID, updatedListIDSecond)
	})

	t.Run("test error get key manager", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKMSRegistry := NewMockKMSRegistry(ctrl)
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(nil, errors.New("some error"))

		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		s, err := New(&Config{
			CSLIndexStore: cslIndexStore,
			CSLVCStore:    cslVCStore,
			VCStatusStore: NewMockVCStatusStore(ctrl),
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			ExternalURL:   "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get KMS")
	})

	t.Run("test error get status processor", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		profile := getTestProfile()
		profile.VCConfig.Status.Type = "undefined"

		mockKMSRegistry := NewMockKMSRegistry(ctrl)
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&vcskms.MockKMS{}, nil)

		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		_, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		s, err := New(&Config{
			CSLIndexStore: cslIndexStore,
			CSLVCStore:    cslVCStore,
			VCStatusStore: NewMockVCStatusStore(ctrl),
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			ExternalURL:   "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})

		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), profile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "unsupported VCStatusListType")
	})

	t.Run("test error from get latest list id from store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKMSRegistry := NewMockKMSRegistry(ctrl)

		s, err := New(&Config{
			CSLIndexStore: newMockCSLIndexStore(func(store *mockCSLIndexStore) {
				store.getLatestListIDErr = errors.New("some error")
			}),
			CSLVCStore:    newMockCSLVCStore(),
			VCStatusStore: NewMockVCStatusStore(ctrl),
			ListSize:      1,
			KMSRegistry:   mockKMSRegistry,
			Crypto: vccrypto.New(&vdrmock.VDRegistry{},
				loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error from put latest list id to store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKMSRegistry := NewMockKMSRegistry(ctrl)

		s, err := New(&Config{
			CSLVCStore: newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
					store.createLatestListIDErr = errors.New("some error")
				}),
			VCStatusStore: NewMockVCStatusStore(ctrl),
			ListSize:      1,
			KMSRegistry:   mockKMSRegistry,
			Crypto: vccrypto.New(&vdrmock.VDRegistry{},
				loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get latestListID from store")
	})

	t.Run("test error create CSL wrapper URL", func(t *testing.T) {
		profile := getTestProfile()

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))

		s, err := New(&Config{
			CSLIndexStore: newMockCSLIndexStore(),
			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.getCSLErr = errors.New("some error")
				}),
			KMSRegistry: mockKMSRegistry,
			ExternalURL: "https://example.com",
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), profile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(),
			"failed to get CSL Index Wrapper from store(s): failed to createCSLIndexWrapper CSL wrapper URL: some error")
	})

	t.Run("test error from CSL VC store", func(t *testing.T) {
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
		ctx := context.Background()

		cslIndexStore := newMockCSLIndexStore()

		_, err := cslIndexStore.GetLatestListID(context.Background())
		require.NoError(t, err)

		s, err := New(&Config{
			CSLIndexStore: cslIndexStore,
			CSLVCStore: newMockCSLVCStore(
				func(store *mockCSLVCStore) {
					store.createErr = errors.New("some error")
				}),
			VCStatusStore: nil,
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			ExternalURL:   "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(ctx, testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to get CSL Index Wrapper from store(s): failed to store VC: some error")
	})

	t.Run("test error put typedID to store - list size too small", func(t *testing.T) {
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			CSLIndexStore: newMockCSLIndexStore(),
			CSLVCStore:    newMockCSLVCStore(),
			VCStatusStore: nil,
			ListSize:      0,
			KMSRegistry:   mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "getUnusedIndex failed")
	})

	t.Run("test error put typedID to store - no available unused indexes", func(t *testing.T) {
		profile := getTestProfile()

		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))

		cslIndexStore := newMockCSLIndexStore()
		cslVCStore := newMockCSLVCStore()

		statusProcessor, err := statustype.GetVCStatusProcessor(vc.BitstringStatusList)
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
			CSLVCStore:    cslVCStore,
			CSLIndexStore: cslIndexStore,
			VCStatusStore: nil,
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			ExternalURL:   "https://localhost:8080",
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "getUnusedIndex failed")
	})

	t.Run("test error from store csl list in store", func(t *testing.T) {
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			CSLVCStore: newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
					store.createErr = errors.New("some error")
				}),
			VCStatusStore: nil,
			KMSRegistry:   mockKMSRegistry,
			ListSize:      1,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store CSL Index Wrapper: some error")
	})

	t.Run("test error update latest list id", func(t *testing.T) {
		mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&vcskms.MockKMS{}, nil)

		s, err := New(&Config{
			CSLVCStore: newMockCSLVCStore(),
			CSLIndexStore: newMockCSLIndexStore(
				func(store *mockCSLIndexStore) {
					store.updateLatestListIDErr = errors.New("some error")
				}),
			VCStatusStore: nil,
			KMSRegistry:   mockKMSRegistry,
			ListSize:      1,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store new list ID: some error")
	})

	t.Run("test error put typedID to store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKMSRegistry := NewMockKMSRegistry(ctrl)
		mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).Times(1).Return(&vcskms.MockKMS{}, nil)

		mockVCStatusStore := NewMockVCStatusStore(ctrl)
		mockVCStatusStore.EXPECT().
			Put(gomock.Any(), testProfileID, testProfileVersion, credID, gomock.Any()).
			Times(1).
			Return(errors.New("some error"))

		s, err := New(&Config{

			CSLIndexStore: newMockCSLIndexStore(),
			CSLVCStore:    newMockCSLVCStore(),
			VCStatusStore: mockVCStatusStore,
			ListSize:      2,
			KMSRegistry:   mockKMSRegistry,
			Crypto: vccrypto.New(
				&vdrmock.VDRegistry{ResolveValue: createDIDDoc()}, loader),
		})
		require.NoError(t, err)

		status, err := s.CreateCSLEntry(context.Background(), testProfile, credID)
		require.Error(t, err)
		require.Nil(t, status)
		require.Contains(t, err.Error(), "failed to store credential status")
	})
}

func getTestProfile() *profileapi.Issuer {
	return &profileapi.Issuer{
		ID:      testProfileID,
		Version: testProfileVersion,
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

func (m *mockCSLIndexStore) Upsert(_ context.Context, cslURL string,
	cslWrapper *credentialstatus.CSLIndexWrapper) error {
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
			s := &Manager{
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

func createDIDDoc() *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
		didID      = "did:test:abc"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := didID + "#key1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            serviceTypeIdentityHub,
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://identityhub.example.com/"),
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

func validateVCStatus(t *testing.T, cslVCStore *mockCSLVCStore, statusID *credentialstatus.StatusListEntry,
	expectedListID credentialstatus.ListID) {
	t.Helper()

	require.Equal(t, string(vc.StatusList2021VCStatus), statusID.TypedID.Type)
	require.Equal(t, "revocation", statusID.TypedID.CustomFields[statustype.StatusPurpose].(string))

	existingStatusListVCID, ok := statusID.TypedID.CustomFields[statustype.StatusListCredential].(string)
	require.True(t, ok)

	chunks := strings.Split(existingStatusListVCID, "/")
	existingStatusVCListID := chunks[len(chunks)-1]
	require.Equal(t, string(expectedListID), existingStatusVCListID)

	cslURL, err := cslVCStore.GetCSLURL("https://localhost:8080", getTestProfile().GroupID, expectedListID)
	require.NoError(t, err)

	vcWrapper, err := cslVCStore.Get(context.Background(), cslURL)
	require.NoError(t, err)

	loader := testutil.DocumentLoader(t)

	statusListVC, err := verifiable.ParseCredential(vcWrapper.VCByte,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
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
