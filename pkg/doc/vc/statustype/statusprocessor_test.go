/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"testing"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func TestGetVCStatusProcessor_StatusList2021VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.StatusList2021VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, StatusList2021Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_BitstringStatusListEntry(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.BitstringStatusList)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, verifiable.V2ContextURI, processor.GetVCContext())
}

func TestGetVCStatusProcessor_RevocationList2021VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.RevocationList2021VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, RevocationList2021Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_RevocationList2020VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.RevocationList2020VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, RevocationList2020Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_UnsupportedVCStatusListType(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.StatusType("unsupported"))
	require.Error(t, err)
	require.Nil(t, processor)
	require.Contains(t, err.Error(), "unsupported VCStatusListType")
}

func TestStatusListProcessor(t *testing.T) {
	s := NewBitstringStatusListProcessor()
	vc, err := s.CreateVC("vcID1", 10, StatusPurposeRevocation, &vcapi.Signer{
		DID:           "did:example:123",
		SignatureType: vcsverifiable.Ed25519Signature2018,
	})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		set, e := processor.IsSet(vc, 1)
		require.NoError(t, e)
		require.False(t, set)

		vc, e = processor.UpdateStatus(vc, true, 1)
		require.NoError(t, e)

		set, e = processor.IsSet(vc, 1)
		require.NoError(t, e)
		require.True(t, set)
	})

	t.Run("invalid status type -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusList2021VCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		_, err := processor.IsSet(vc, 1)
		require.ErrorContains(t, err, "unsupported status list type")
	})

	t.Run("non-multibase decoding -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType: StatusListBitstringVCSubjectType,
		}

		_, e := processor.IsSet(vc, 1)
		require.ErrorContains(t, e, "failed to decode encodedList")
	})

	t.Run("invalid multibase encoding -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64urlPad,
		}

		_, e := processor.IsSet(vc, 1)
		require.ErrorContains(t, e, "failed to decode encodedList")
	})

	t.Run("no subject -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		_, e := processor.IsSet(&verifiable.Credential{}, 1)
		require.ErrorContains(t, e, "invalid subject field structure")
	})

	t.Run("invalid subject type -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		invalidVC, e := verifiable.ParseCredential([]byte(invalidTypeCSLVC),
			verifiable.WithCredDisableValidation(), verifiable.WithDisabledProofCheck())
		require.NoError(t, e)

		_, e = processor.IsSet(invalidVC, 1)
		require.ErrorContains(t, e, "failed to get status list type: invalid 'type' type")
	})

	t.Run("invalid subject encodedList -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		invalidVC, e := verifiable.ParseCredential([]byte(invalidEncodedListCSLVC),
			verifiable.WithCredDisableValidation(), verifiable.WithDisabledProofCheck())
		require.NoError(t, e)

		_, e = processor.IsSet(invalidVC, 1)
		require.ErrorContains(t, e, "failed to get encodedList: invalid 'encodedList' type")
	})

	t.Run("updateStatus - invalid status type -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusList2021VCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		_, e := processor.UpdateStatus(vc, true, 1)
		require.ErrorContains(t, e, "unsupported status list type")
	})

	t.Run("updateStatus - invalid subject encodedList -> error", func(t *testing.T) {
		processor := &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		}

		invalidVC, e := verifiable.ParseCredential([]byte(invalidEncodedListCSLVC),
			verifiable.WithCredDisableValidation(), verifiable.WithDisabledProofCheck())
		require.NoError(t, e)

		_, e = processor.UpdateStatus(invalidVC, true, 1)
		require.ErrorContains(t, e, "failed to get encodedList: invalid 'encodedList' type")
	})
}

const invalidEncodedListCSLVC = `{
 "@context": [
   "https://www.w3.org/ns/credentials/v2"
 ],
 "credentialSubject": {
   "encodedList": 123,
   "id": "did:web:example.com:12345#list",
   "statusPurpose": "revocation",
   "type": "BitstringStatusList"
 },
 "id": "did:web:example.com:12345",
 "issuer": "did:test:abc",
 "type": [
   "VerifiableCredential",
   "BitstringStatusListCredential"
 ]
}`

const invalidTypeCSLVC = `{
 "@context": [
   "https://www.w3.org/ns/credentials/v2"
 ],
 "credentialSubject": {
   "encodedList": "uH4sIAAAAAAAA_-zAgQAAAACAoP2pF6kAAAAAAAAAAAAAAAAAAACgOgAA__-N53xXgD4AAA",
   "id": "did:web:example.com:12345#list",
   "statusPurpose": "revocation",
   "type": 123
 },
 "id": "did:web:example.com:12345",
 "issuer": "did:test:abc",
 "type": [
   "VerifiableCredential",
   "BitstringStatusListCredential"
 ]
}`
