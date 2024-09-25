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

func Test_statusList2021Processor_ValidateStatus(t *testing.T) {
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
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "",
						"statusPurpose":        "2",
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
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListCredential": "",
						"statusPurpose":        "2",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusListCredential empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   "2",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusPurpose empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStatusList2021Processor()
			if err := s.ValidateStatus(tt.args.vcStatus); (err != nil) != tt.wantErr {
				t.Errorf("validateVCStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_statusList2021Processor_CreateVC(t *testing.T) {
	s := NewStatusList2021Processor()
	vc, err := s.CreateVC("vcID1", 10, &vcapi.Signer{
		DID:           "did:example:123",
		SignatureType: vcsverifiable.JSONWebSignature2020,
	})
	vcc := vc.Contents()

	require.NoError(t, err)
	require.Equal(t, "vcID1", vcc.ID)
	require.Equal(t, []string{
		vcutil.DefVCContext,
		StatusList2021Context,
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"}, vcc.Context)
	require.Equal(t, []string{vcType, statusList2021VCType}, vcc.Types)
	require.Equal(t, &verifiable.Issuer{ID: "did:example:123"}, vcc.Issuer)
	encodeBits, err := bitstring.NewBitString(bitStringSize).EncodeBits()
	require.NoError(t, err)
	require.Equal(t, []verifiable.Subject{{
		ID: "vcID1#list",
		CustomFields: map[string]interface{}{
			"type":          "StatusList2021",
			"statusPurpose": "revocation",
			"encodedList":   encodeBits,
		},
	}}, vcc.Subject)
}

func Test_statusList2021Processor_CreateVCStatus(t *testing.T) {
	s := NewStatusList2021Processor()
	statusID := s.CreateVCStatus("1", "vcID2", StatusPurposeRevocation)

	require.Equal(t, string(vcapi.StatusList2021VCStatus), statusID.Type)
	require.Equal(t, verifiable.CustomFields{
		StatusPurpose:        "revocation",
		StatusListIndex:      "1",
		StatusListCredential: "vcID2",
	}, statusID.CustomFields)
}

func Test_statusList2021Processor_GetStatusListIndex(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			StatusListIndex: "abc",
		},
	}

	s := NewStatusList2021Processor()
	index, err := s.GetStatusListIndex(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to get statusListIndex")
	require.Equal(t, -1, index)

	vcStatus.CustomFields[StatusListIndex] = "1"
	index, err = s.GetStatusListIndex(vcStatus)
	require.NoError(t, err)

	require.Equal(t, 1, index)
}

func Test_statusList2021Processor_GetStatusVCURI(t *testing.T) {
	vcStatus := &verifiable.TypedID{
		CustomFields: map[string]interface{}{
			StatusListCredential: 1,
		},
	}

	s := NewStatusList2021Processor()
	vcURI, err := s.GetStatusVCURI(vcStatus)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to cast URI of statusListCredential")
	require.Empty(t, vcURI)

	vcStatus.CustomFields[StatusListCredential] = "https://example.com/1"
	vcURI, err = s.GetStatusVCURI(vcStatus)
	require.NoError(t, err)

	require.Equal(t, "https://example.com/1", vcURI)
}

func Test_statusList2021Processor_GetVCContext(t *testing.T) {
	s := NewStatusList2021Processor()

	require.Equal(t, "https://w3id.org/vc/status-list/2021/v1", s.GetVCContext())
}
