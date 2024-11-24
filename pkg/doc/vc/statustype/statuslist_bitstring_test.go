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
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func Test_BitstringStatusListProcessor_ValidateStatus(t *testing.T) {
	type args struct {
		vcStatus *verifiable.TypedID
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "status purpose revocation -> OK",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeRevocation,
					},
				},
			},
		},
		{
			name: "Error not exist",
			args: args{
				vcStatus: nil,
			},
			wantErr: "vc status not found",
		},
		{
			name: "Error status not supported",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "statusPurpose",
				},
			},
			wantErr: "vc status statusPurpose not supported",
		},
		{
			name: "Error statusListIndex empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeRevocation,
					},
				},
			},
			wantErr: "statusListIndex field not found in vc status",
		},
		{
			name: "Error statusListCredential empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   StatusPurposeRevocation,
					},
				},
			},
			wantErr: "statusListCredential field not found in vc status",
		},
		{
			name: "Error statusPurpose empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
					},
				},
			},
			wantErr: "statusPurpose field not found in vc status",
		},
		{
			name: "Unsupported statusPurpose error",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        "some-purpose",
					},
				},
			},
			wantErr: "some-purpose is an unsupported statusPurpose",
		},
		{
			name: "statusPurpose statusMessage -> statusMessage array size must be 2",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
					},
				},
			},
			wantErr: "statusMessage array size must be 2",
		},
		{
			name: "statusPurpose statusMessage -> status field not found",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
						"statusMessage": []interface{}{
							map[string]interface{}{
								"message": "value",
							},
							map[string]interface{}{
								"message": "value",
							},
						},
					},
				},
			},
			wantErr: "status field not found",
		},
		{
			name: "statusPurpose statusMessage -> message field not found",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
						"statusMessage": []interface{}{
							map[string]interface{}{
								"status": "value",
							},
							map[string]interface{}{
								"status": "value",
							},
						},
					},
				},
			},
			wantErr: "message field not found",
		},
		{
			name: "statusPurpose statusMessage > status field must be a hex string",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
						"statusMessage": []interface{}{
							map[string]interface{}{
								"status":  "1",
								"message": "message_1",
							},
							map[string]interface{}{
								"status":  "2",
								"message": "message_2",
							},
						},
					},
				},
			},
			wantErr: "status field must be a hex string",
		},
		{
			name: "statusPurpose statusMessage > default statusSize -> OK",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
						"statusMessage": []interface{}{
							map[string]interface{}{
								"status":  "0x1",
								"message": "message_1",
							},
							map[string]interface{}{
								"status":  "0x2",
								"message": "message_2",
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "statusPurpose statusMessage > statusSize 2 -> OK",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "BitstringStatusListEntry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "https://example.com/credentials/status/8",
						"statusPurpose":        StatusPurposeMessage,
						"statusSize":           "2",
						"statusMessage": []interface{}{
							map[string]interface{}{
								"status":  "0x1",
								"message": "message_1",
							},
							map[string]interface{}{
								"status":  "0x2",
								"message": "message_2",
							},
							map[string]interface{}{
								"status":  "0x3",
								"message": "message_3",
							},
							map[string]interface{}{
								"status":  "0x4",
								"message": "message_4",
							},
						},
					},
				},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewBitstringStatusListProcessor()
			err := s.ValidateStatus(tt.args.vcStatus)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("validateVCStatus() error = %v, wantErr %s", err, tt.wantErr)
				}
			} else if tt.wantErr != "" {
				t.Errorf("validateVCStatus() error = %v, wantErr %s", err, tt.wantErr)
			}
		})
	}
}

func Test_BitstringStatusListProcessor_CreateVC(t *testing.T) {
	s := NewBitstringStatusListProcessor()
	vc, err := s.CreateVC("vcID1", 10, &vcapi.Signer{
		DID:           "did:example:123",
		SignatureType: vcsverifiable.Ed25519Signature2018,
	})
	require.NoError(t, err)

	vcc := vc.Contents()

	require.NoError(t, err)
	require.Equal(t, "vcID1", vcc.ID)
	require.Equal(t, []string{
		verifiable.V2ContextURI,
		"https://w3id.org/security/suites/ed25519-2018/v1"}, vcc.Context)
	require.Equal(t, []string{vcType, StatusListBitstringVCType}, vcc.Types)
	require.Equal(t, &verifiable.Issuer{ID: "did:example:123"}, vcc.Issuer)
	encodeBits, err := bitstring.NewBitString(bitStringSize,
		bitstring.WithMultibaseEncoding(multibase.Base64url)).EncodeBits()
	require.NotEmpty(t, vc.ToRawClaimsMap()["validFrom"])
	require.NoError(t, err)
	require.Equal(t, []verifiable.Subject{{
		ID: "vcID1#list",
		CustomFields: map[string]interface{}{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encodeBits,
		},
	}}, vcc.Subject)
}

func Test_BitstringStatusListProcessor_CreateVCStatus(t *testing.T) {
	s := NewBitstringStatusListProcessor()

	t.Run("status purpose revocation", func(t *testing.T) {
		statusID := s.CreateVCStatus("1", "vcID2", StatusPurposeRevocation)

		require.Equal(t, StatusListBitstringEntryType, statusID.Type)
		require.Equal(t, verifiable.CustomFields{
			StatusPurpose:        "revocation",
			StatusListIndex:      "1",
			StatusListCredential: "vcID2",
		}, statusID.CustomFields)
	})

	t.Run("status purpose suspension", func(t *testing.T) {
		statusID := s.CreateVCStatus("1", "vcID2", StatusPurposeSuspension)

		require.Equal(t, StatusListBitstringEntryType, statusID.Type)
		require.Equal(t, verifiable.CustomFields{
			StatusPurpose:        "suspension",
			StatusListIndex:      "1",
			StatusListCredential: "vcID2",
		}, statusID.CustomFields)
	})

	t.Run("status purpose statusMessage", func(t *testing.T) {
		statusID := s.CreateVCStatus("1", "vcID2", StatusPurposeMessage,
			vcapi.Field{Key: StatusReference, Value: "https://example.org/status-dictionary/"},
			vcapi.Field{Key: "statusSize", Value: "1"},
			vcapi.Field{Key: "statusMessage", Value: []interface{}{
				map[string]interface{}{
					"status":  "0x1",
					"message": "message_1",
				},
				map[string]interface{}{
					"status":  "0x2",
					"message": "message_2",
				},
			}},
		)
		require.Equal(t, StatusListBitstringEntryType, statusID.Type)
		require.Equal(t, verifiable.CustomFields{
			StatusPurpose:        "statusMessage",
			StatusListIndex:      "1",
			StatusListCredential: "vcID2",
			StatusSize:           "1",
			StatusReference:      "https://example.org/status-dictionary/",
			StatusMessage: []interface{}{
				map[string]interface{}{
					"status":  "0x1",
					"message": "message_1",
				},
				map[string]interface{}{
					"status":  "0x2",
					"message": "message_2",
				},
			},
		}, statusID.CustomFields)

		require.NoError(t, s.ValidateStatus(statusID))
	})
}

func Test_BitstringStatusListProcessor_GetStatusListIndex(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			StatusListIndex: "abc",
		},
	}

	s := NewBitstringStatusListProcessor()
	index, err := s.GetStatusListIndex(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to get statusListIndex")
	require.Equal(t, -1, index)

	vcStatus.CustomFields[StatusListIndex] = "1"
	index, err = s.GetStatusListIndex(vcStatus)
	require.NoError(t, err)

	require.Equal(t, 1, index)
}

func Test_BitstringStatusListProcessor_GetStatusVCURI(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			StatusListCredential: 1,
		},
	}

	s := NewBitstringStatusListProcessor()
	vcURI, err := s.GetStatusVCURI(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to cast URI of statusListCredential")
	require.Empty(t, vcURI)

	vcStatus.CustomFields[StatusListCredential] = "https://example.com/1"
	vcURI, err = s.GetStatusVCURI(vcStatus)
	require.NoError(t, err)

	require.Equal(t, "https://example.com/1", vcURI)
}

func Test_BitstringStatusListProcessor_GetVCContext(t *testing.T) {
	s := NewBitstringStatusListProcessor()

	require.Equal(t, "https://www.w3.org/ns/credentials/v2", s.GetVCContext())
}

func Test_BitstringStatusList_IsSet(t *testing.T) {
	vc, err := verifiable.ParseCredential([]byte(bitstringCSLVC),
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(),
	)
	require.NoError(t, err)

	s := NewBitstringStatusListProcessor()

	set, err := s.IsSet(vc, 4000)
	require.NoError(t, err)
	require.True(t, set)
}

const bitstringCSLVC = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "id": "https://dhs-svip.github.io/ns/uscis/status/3",
  "type": [
    "VerifiableCredential",
    "BitstringStatusListCredential"
  ],
  "credentialSubject": {
    "id": "https://dhs-svip.github.io/ns/uscis/status/3#list",
    "type": "BitstringStatusList",
    "encodedList": "uH4sIAAAAAAAAA-3OMQEAAAgDoEU3ugEWwENIQMI3cx0AAAAAAAAAAAAAAAAAAACgLGiNcIEAQAAA",
    "statusPurpose": "revocation"
  },
  "issuer": "did:web:dhs-svip.github.io:ns:uscis:oidp",
  "proof": {
    "type": "DataIntegrityProof",
    "verificationMethod": "did:web:dhs-svip.github.io:ns:uscis:oidp#zDnaekqKLkVN1HqzBxy1Ti8niyCRxWkKr6cxDvX6P4qXDBATd",
    "cryptosuite": "ecdsa-rdfc-2019",
    "proofPurpose": "assertionMethod",
    "proofValue": "zLLLMLuL6feiYZ1vDU7AVaJGRpmbbi1bf8Xv9JL15sW6aZTVzrfJqb9UFPWmgPD3Mnk5C3EpN3eKvzC27fdVM3Y6"
  }
}`
