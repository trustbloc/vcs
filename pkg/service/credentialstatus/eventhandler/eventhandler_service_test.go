/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eventhandler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vcs/internal/mock/vcskms"

	"github.com/trustbloc/did-go/doc/did"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	statusBytePositionIndex = 1
	profileID               = "testProfileID"
	profileVersion          = "v1.0"
	listUUID                = "d715ce6b-0df5-4fe8-ab19-be9bc6dada9c"
	cslURL                  = "https://localhost:8080/issuer/profiles/externalID/credentials/status/" + listUUID
	cslWrapperBytes         = `{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
    ],
    "credentialSubject": {
      "encodedList": "H4sIAAAAAAAA_-zAgQAAAACAoP2pF6kAAAAAAAAAAAAAAAAAAACgOgAA__-N53xXgD4AAA",
      "id": "` + cslURL + `#list",
      "statusPurpose": "revocation",
      "type": "StatusList2021"
    },
    "id": "` + cslURL + `",
    "issuanceDate": "2023-03-22T11:34:05.091926539Z",
    "issuer": "did:test:abc",
    "type": [
      "VerifiableCredential",
      "StatusList2021Credential"
    ]
  }
}`
	cslWrapperBytesInvalidEncodedList = `{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
    ],
    "credentialSubject": {
      "encodedList": "ddddd",
      "id": "` + cslURL + `#list",
      "statusPurpose": "revocation",
      "type": "StatusList2021"
    },
    "id": "` + cslURL + `",
    "issuanceDate": "2023-03-22T11:34:05.091926539Z",
    "issuer": "did:test:abc",
    "type": [
      "VerifiableCredential",
      "StatusList2021Credential"
    ]
  }
}`
	cslWrapperBytesInvalidProof = `{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
    ],
    "credentialSubject": {
      "encodedList": "H4sIAAAAAAAA_-zAgQAAAACAoP2pF6kAAAAAAAAAAAAAAAAAAACgOgAA__-N53xXgD4AAA",
      "id": "` + cslURL + `#list",
      "statusPurpose": "revocation",
      "type": "StatusList2021"
    },
    "id": "` + cslURL + `",
    "issuanceDate": "2023-03-22T11:34:05.091926539Z",
    "issuer": "did:test:abc",
    "type": [
      "VerifiableCredential",
      "StatusList2021Credential"
    ],
	"proof": {
		"proofPurpose": 123
    }
  }
}`
)

func TestService_HandleEvent(t *testing.T) {
	profile := getTestProfile()
	loader := testutil.DocumentLoader(t)
	ctx := context.Background()
	mockProfileSrv := NewMockProfileService(gomock.NewController(t))
	mockProfileSrv.EXPECT().GetProfile(gomock.Any(), gomock.Any()).AnyTimes().Return(profile, nil)
	mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
	mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
	crypto := vccrypto.New(
		&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)

	t.Run("OK", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.HandleEvent(ctx, event)
		require.NoError(t, err)

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, true)
	})

	t.Run("OK invalid event type", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		event.Type = spi.IssuerOIDCInteractionInitiated

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.HandleEvent(ctx, event)
		require.NoError(t, err)

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)
	})
	t.Run("Error invalid event payload", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		event.Data = []byte(`   123`)

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.HandleEvent(ctx, event)
		require.Error(t, err)

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)
	})
}

func TestService_handleEventPayload(t *testing.T) {
	profile := getTestProfile()
	loader := testutil.DocumentLoader(t)
	ctx := context.Background()
	mockProfileSrv := NewMockProfileService(gomock.NewController(t))
	mockProfileSrv.EXPECT().GetProfile(gomock.Any(), gomock.Any()).AnyTimes().Return(profile, nil)
	mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
	mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
	crypto := vccrypto.New(
		&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)

	t.Run("OK", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.NoError(t, err)

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, true)
	})

	t.Run("Error getCSLWrapper", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "get CSL VC wrapper failed")
	})

	t.Run("Error bitstring.DecodeBits", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytesInvalidEncodedList), &cslWrapper)
		require.NoError(t, err)

		cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "get encodedList from CSL customFields failed")

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
	})

	t.Run("Error bitString.Set failed", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     -1,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "bitString.Set failed")

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)
	})

	t.Run("Error failed to sign CSL", func(t *testing.T) {
		mockProfileSrvErr := NewMockProfileService(gomock.NewController(t))
		mockProfileSrvErr.EXPECT().GetProfile(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrvErr,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to sign CSL")

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)
	})

	t.Run("Error cslStore.Upsert failed", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		cslStore.createErr = errors.New("some error")

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "cslStore.Upsert failed")

		cslWrapper, err = cslStore.Get(ctx, cslURL)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)
	})
}

func TestService_signCSL(t *testing.T) {
	profile := getTestProfile()
	loader := testutil.DocumentLoader(t)
	ctx := context.Background()
	mockProfileSrv := NewMockProfileService(gomock.NewController(t))
	mockProfileSrv.EXPECT().GetProfile(gomock.Any(), gomock.Any()).AnyTimes().Return(profile, nil)
	mockKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
	mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(&vcskms.MockKMS{}, nil)
	crypto := vccrypto.New(
		&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:test:abc")}, loader)

	t.Run("OK", func(t *testing.T) {
		cslStore := newMockCSLVCStore()

		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		err = cslStore.Upsert(ctx, cslWrapper.VC.Contents().ID, cslWrapper)
		require.NoError(t, err)

		s := New(&Config{
			DocumentLoader: loader,
			CSLVCStore:     cslStore,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         crypto,
		})

		signedCSL, err := s.signCSL(profileID, profileVersion, cslWrapper.VC)
		require.NoError(t, err)
		require.NotEmpty(t, signedCSL)
		cslWrapper.VC = getVerifiedCSL(t, signedCSL, loader, statusBytePositionIndex, false)
		require.NotEmpty(t, cslWrapper.VC.Proofs)
	})

	t.Run("Error failed to get profile", func(t *testing.T) {
		mockProfileSrvErr := NewMockProfileService(gomock.NewController(t))
		mockProfileSrvErr.EXPECT().GetProfile(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		s := New(&Config{
			ProfileService: mockProfileSrvErr,
		})

		signedCSL, err := s.signCSL(profileID, profileVersion, nil)
		require.Empty(t, signedCSL)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get profile")
	})

	t.Run("Error failed to get KMS", func(t *testing.T) {
		mockKMSRegistryErr := NewMockKMSRegistry(gomock.NewController(t))
		mockKMSRegistryErr.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistryErr,
		})

		signedCSL, err := s.signCSL(profileID, profileVersion, nil)
		require.Empty(t, signedCSL)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get KMS")
	})

	t.Run("Error prepareSigningOpts failed", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytesInvalidProof), &cslWrapper)
		require.NoError(t, err)

		cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithCredDisableValidation(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		s := New(&Config{
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
		})

		signedCSL, err := s.signCSL(profileID, profileVersion, cslWrapper.VC)
		require.Empty(t, signedCSL)
		require.Error(t, err)
		require.ErrorContains(t, err, "prepareSigningOpts failed")
	})

	t.Run("Error sign CSL failed", func(t *testing.T) {
		cryptoErr := vccrypto.New(
			&vdrmock.VDRegistry{ResolveErr: errors.New("some error")}, loader)
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		s := New(&Config{
			DocumentLoader: loader,
			ProfileService: mockProfileSrv,
			KMSRegistry:    mockKMSRegistry,
			Crypto:         cryptoErr,
		})

		signedCSL, err := s.signCSL(profileID, profileVersion, cslWrapper.VC)
		require.Empty(t, signedCSL)
		require.Error(t, err)
		require.ErrorContains(t, err, "sign CSL failed")
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

//nolint:unparam
func getVerifiedCSL(
	t *testing.T, cslBytes []byte, dl ld.DocumentLoader, index int, expectedStatus bool) *verifiable.Credential {
	t.Helper()
	csl, err := verifiable.ParseCredential(cslBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(dl))
	require.NoError(t, err)

	credSubject := csl.Contents().Subject
	require.NotEmpty(t, credSubject[0].CustomFields["encodedList"].(string))
	bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	require.NoError(t, err)
	bitSet, err := bitString.Get(index)
	require.NoError(t, err)
	require.Equal(t, expectedStatus, bitSet)

	return csl
}

func createStatusUpdatedEvent(
	t *testing.T, cslURL, profileID, profileVersion string, index int, status bool) *spi.Event {
	t.Helper()

	ep := credentialstatus.UpdateCredentialStatusEventPayload{
		CSLURL:         cslURL,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		Index:          index,
		Status:         status,
	}

	payload, err := json.Marshal(ep)
	require.NoError(t, err)

	return spi.NewEventWithPayload(
		cslURL,
		"test_source",
		spi.CredentialStatusStatusUpdated,
		payload)
}

type mockCSLVCStore struct {
	createErr error
	getCSLErr error
	findErr   error
	s         map[string]*credentialstatus.CSLVCWrapper
}

func newMockCSLVCStore() *mockCSLVCStore {
	s := &mockCSLVCStore{
		s: map[string]*credentialstatus.CSLVCWrapper{},
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
		ID:            "did:example:123456789abcdefghi#did-communication",
		RecipientKeys: []string{creator},
		Priority:      0,
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
