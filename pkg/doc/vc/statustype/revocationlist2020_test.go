/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func Test_revocationList2020Processor_ValidateStatus(t *testing.T) {
	type args struct {
		vcStatus *verifiable.TypedID
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "RevocationList2020Status",
					CustomFields: map[string]interface{}{
						"revocationListIndex":      "1",
						"revocationListCredential": "",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Error not exist",
			args: args{
				vcStatus: nil,
			},
			wantErr: true,
		},
		{
			name: "Error status not supported",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "statusPurpose",
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusListIndex empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "RevocationList2020Status",
					CustomFields: map[string]interface{}{
						"revocationListCredential": "",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusListCredential empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "RevocationList2020Status",
					CustomFields: map[string]interface{}{
						"revocationListIndex": "1",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewRevocationList2020Processor()
			if err := s.ValidateStatus(tt.args.vcStatus); (err != nil) != tt.wantErr {
				t.Errorf("validateVCStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_revocationList2020Processor_CreateVC(t *testing.T) {
	s := NewRevocationList2020Processor()

	vc, err := s.CreateVC("vcID1", 10, StatusPurposeSuspension, &vcapi.Signer{
		DID:           "did:example:123",
		SignatureType: vcsverifiable.JSONWebSignature2020,
	})
	require.ErrorContains(t, err, "unsupported statusPurpose: suspension")
	require.Nil(t, vc)

	vc, err = s.CreateVC("vcID1", 10, StatusPurposeRevocation, &vcapi.Signer{
		DID:           "did:example:123",
		SignatureType: vcsverifiable.JSONWebSignature2020,
	})
	require.NoError(t, err)

	vcc := vc.Contents()

	require.NoError(t, err)
	require.Equal(t, "vcID1", vcc.ID)
	require.Equal(t, []string{
		vcutil.DefVCContext,
		RevocationList2020Context,
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"}, vcc.Context)
	require.Equal(t, []string{vcType, revocationList2020VCType}, vcc.Types)
	require.Equal(t, &verifiable.Issuer{ID: "did:example:123"}, vcc.Issuer)
	encodeBits, err := bitstring.NewBitString(bitStringSize).EncodeBits()
	require.NoError(t, err)
	require.Equal(t, toVerifiableSubject(credentialSubject{
		ID:          "vcID1#list",
		Type:        "RevocationList2020",
		EncodedList: encodeBits,
	}), vcc.Subject)
}

func Test_revocationList2020Processor_CreateVCStatus(t *testing.T) {
	s := NewRevocationList2020Processor()
	statusID := s.CreateVCStatus("1", "vcID2", "")

	require.Equal(t, string(vcapi.RevocationList2020VCStatus), statusID.Type)
	require.Equal(t, verifiable.CustomFields{
		RevocationListIndex:      "1",
		RevocationListCredential: "vcID2",
	}, statusID.CustomFields)
}

func Test_revocationList2020Processor_GetStatusListIndex(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			RevocationListIndex: "abc",
		},
	}

	s := NewRevocationList2020Processor()
	index, err := s.GetStatusListIndex(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to get revocationListIndex")
	require.Equal(t, -1, index)

	vcStatus.CustomFields[RevocationListIndex] = "1"
	index, err = s.GetStatusListIndex(vcStatus)
	require.NoError(t, err)

	require.Equal(t, 1, index)
}

func Test_revocationList2020Processor_GetStatusVCURI(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			RevocationListCredential: 1,
		},
	}

	s := NewRevocationList2020Processor()
	uri, err := s.GetStatusVCURI(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to cast URI of revocationListCredential")
	require.Empty(t, uri)

	vcStatus.CustomFields[RevocationListCredential] = "https://example.com/1"
	uri, err = s.GetStatusVCURI(vcStatus)
	require.NoError(t, err)

	require.Equal(t, "https://example.com/1", uri)
}

func Test_revocationList2020Processor_GetVCContext(t *testing.T) {
	s := NewRevocationList2020Processor()
	require.Equal(t, "https://w3id.org/vc-revocation-list-2020/v1", s.GetVCContext())
}

func TestRevocationList2020Processor_GetStatusPurpose(t *testing.T) {
	s := NewRevocationList2020Processor()
	purpose, err := s.GetStatusPurpose(&verifiable.TypedID{})
	require.NoError(t, err)
	require.Equal(t, StatusPurposeRevocation, purpose)
}
