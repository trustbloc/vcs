/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eventhandler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
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
	//nolint
	signedCSL = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "credentialSubject": {
    "encodedList": "H4sIAAAAAAAA_-zAgQAAAACAoP2pF6kAAAAAAAAAAAAAAAAAAACgOgAA__-N53xXgD4AAA",
    "id": "https://localhost:8080/issuer/profiles/externalID/credentials/status/d715ce6b-0df5-4fe8-ab19-be9bc6dada9c#list",
    "statusPurpose": "revocation",
    "type": "StatusList2021"
  },
  "id": "https://localhost:8080/issuer/profiles/externalID/credentials/status/d715ce6b-0df5-4fe8-ab19-be9bc6dada9c",
  "issuanceDate": "2023-03-22T11:34:05.091926539Z",
  "issuer": "did:test:abc",
  "proof": {
    "created": "2024-12-03T16:00:21.446133-05:00",
    "proofPurpose": "authentication",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:test:abc#key1"
  },
  "type": [
    "VerifiableCredential",
    "StatusList2021Credential"
  ]
}`
)

func TestService_HandleEvent(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	ctx := context.Background()

	t.Run("OK", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()
		cslService.EXPECT().SignCSL(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(profileID, profileVersion string, csl *verifiable.Credential) ([]byte, error) {
				cslBytes, e := json.Marshal(csl)
				require.NoError(t, e)

				getVerifiedCSL(t, cslBytes, loader, statusBytePositionIndex, true)

				return []byte(signedCSL), nil
			},
		)
		cslService.EXPECT().UpsertCSLVCWrapper(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.HandleEvent(ctx, event)
		require.NoError(t, err)
	})

	t.Run("OK invalid event type", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		event.Type = spi.IssuerOIDCInteractionInitiated

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.HandleEvent(ctx, event)
		require.NoError(t, err)
	})

	t.Run("Error invalid event payload", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), gomock.Any()).Return(cslWrapper, nil).AnyTimes()

		event := createStatusUpdatedEvent(
			t, cslURL, profileID, profileVersion, statusBytePositionIndex, true)

		event.Data = []byte("invalid")

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.HandleEvent(ctx, event)
		require.Error(t, err)
	})
}

func TestService_handleEventPayload(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	ctx := context.Background()

	t.Run("OK", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()
		cslService.EXPECT().SignCSL(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(profileID, profileVersion string, csl *verifiable.Credential) ([]byte, error) {
				cslBytes, e := json.Marshal(csl)
				require.NoError(t, e)

				getVerifiedCSL(t, cslBytes, loader, statusBytePositionIndex, true)

				return []byte(signedCSL), nil
			},
		)
		cslService.EXPECT().UpsertCSLVCWrapper(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.NoError(t, err)
	})

	t.Run("Error getCSLWrapper", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(nil, errors.New("getCSLWrapper error"))

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "get CSL VC wrapper failed")
	})

	t.Run("Error bitstring.DecodeBits", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytesInvalidEncodedList), &cslWrapper)
		require.NoError(t, err)

		cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to update status: failed to decode encodedList")
	})

	t.Run("Error bitString.Set failed", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     -1,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "bitString.Set failed")
	})

	t.Run("Error failed to sign CSL", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()
		cslService.EXPECT().SignCSL(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed to sign CSL"))

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to sign CSL")
	})

	t.Run("Error cslStore.Upsert failed", func(t *testing.T) {
		var cslWrapper *credentialstatus.CSLVCWrapper
		err := json.Unmarshal([]byte(cslWrapperBytes), &cslWrapper)
		require.NoError(t, err)
		cslWrapper.VC = getVerifiedCSL(t, cslWrapper.VCByte, loader, statusBytePositionIndex, false)

		cslService := NewMockCSLService(gomock.NewController(t))
		cslService.EXPECT().GetCSLVCWrapper(gomock.Any(), cslURL).Return(cslWrapper, nil).AnyTimes()
		cslService.EXPECT().SignCSL(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte(signedCSL), nil)
		cslService.EXPECT().UpsertCSLVCWrapper(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("cslStore.Upsert failed"))

		eventPayload := credentialstatus.UpdateCredentialStatusEventPayload{
			CSLURL:    cslURL,
			ProfileID: profileID,
			Index:     statusBytePositionIndex,
			Status:    true,
		}

		s := New(&Config{
			CSLService: cslService,
		})

		err = s.handleEventPayload(ctx, eventPayload)
		require.Error(t, err)
		require.ErrorContains(t, err, "cslStore.Upsert failed")
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

	var bitString *bitstring.BitString

	statusType, ok := credSubject[0].CustomFields["type"].(string)
	require.True(t, ok)

	if statusType == "BitstringStatusList" {
		bitString, err = bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string),
			bitstring.WithMultibaseEncoding(multibase.Base64url))
	} else {
		bitString, err = bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	}

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
