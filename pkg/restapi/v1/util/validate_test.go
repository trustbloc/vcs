/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/samber/lo"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestValidateAuthorizationDetails(t *testing.T) {
	type args struct {
		ad []common.AuthorizationDetails
	}
	tests := []struct {
		name          string
		args          args
		want          []*issuecredential.AuthorizationDetails
		wantErr       bool
		errorContains string
	}{
		{
			name: "Success Based on credentialConfigurationID",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						CredentialConfigurationId: lo.ToPtr("UniversityDegreeCredential"),
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition:      nil,
						Format:                    nil,
					},
					{
						CredentialConfigurationId: lo.ToPtr("PermanentResidentCard"),
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition:      nil,
						Format:                    nil,
					},
				},
			},
			want: []*issuecredential.AuthorizationDetails{
				{
					Type:                      "openid_credential",
					Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
					CredentialConfigurationID: "UniversityDegreeCredential",
					Format:                    "",
					CredentialDefinition:      nil,
				},
				{
					Type:                      "openid_credential",
					Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
					CredentialConfigurationID: "PermanentResidentCard",
					Format:                    "",
					CredentialDefinition:      nil,
				},
			},
			wantErr:       false,
			errorContains: "",
		},
		{
			name: "Success Based on credentialFormat",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						CredentialConfigurationId: nil,
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition: &common.CredentialDefinition{
							Context: lo.ToPtr([]string{"https://example.com/context/1", "https://example.com/context/2"}),
							CredentialSubject: lo.ToPtr(map[string]interface{}{
								"key": "value",
							}),
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: lo.ToPtr("jwt_vc_json"),
					},
					{
						CredentialConfigurationId: nil,
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition: &common.CredentialDefinition{
							Context: lo.ToPtr([]string{"https://example.com/context/1", "https://example.com/context/2"}),
							CredentialSubject: lo.ToPtr(map[string]interface{}{
								"key": "value",
							}),
							Type: []string{"VerifiableCredential", "PermanentResidentCard"},
						},
						Format: lo.ToPtr("jwt_vc_json"),
					},
				},
			},
			want: []*issuecredential.AuthorizationDetails{
				{
					Type:                      "openid_credential",
					Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
					CredentialConfigurationID: "",
					Format:                    vcsverifiable.OIDCFormat("jwt_vc_json"),
					CredentialDefinition: &issuecredential.CredentialDefinition{
						Context: []string{"https://example.com/context/1", "https://example.com/context/2"},
						CredentialSubject: map[string]interface{}{
							"key": "value",
						},
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
				},
				{
					Type:                      "openid_credential",
					Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
					CredentialConfigurationID: "",
					Format:                    vcsverifiable.OIDCFormat("jwt_vc_json"),
					CredentialDefinition: &issuecredential.CredentialDefinition{
						Context: []string{"https://example.com/context/1", "https://example.com/context/2"},
						CredentialSubject: map[string]interface{}{
							"key": "value",
						},
						Type: []string{"VerifiableCredential", "PermanentResidentCard"},
					},
				},
			},
			wantErr:       false,
			errorContains: "",
		},
		{
			name: "Error invalid type",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						Type: "unknown",
					},
				},
			},
			want:          nil,
			wantErr:       true,
			errorContains: "invalid-value[authorization_details.type]: type should be 'openid_credential'",
		},
		{
			name: "Error: credentialFormat: invalid format",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						CredentialConfigurationId: nil,
						Locations:                 nil,
						Type:                      "openid_credential",
						CredentialDefinition: &common.CredentialDefinition{
							Context: lo.ToPtr([]string{"https://example.com/context/1", "https://example.com/context/2"}),
							CredentialSubject: lo.ToPtr(map[string]interface{}{
								"key": "value",
							}),
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: lo.ToPtr("unknown"),
					},
				},
			},
			want:    nil,
			wantErr: true,
			errorContains: "invalid-value[authorization_details.format]: " +
				"unsupported vc format unknown, use one of next [jwt_vc_json-ld, ldp_vc]",
		},
		{
			name: "Error: credentialFormat: empty CredentialDefinition",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						CredentialConfigurationId: nil,
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition:      nil,
						Format:                    lo.ToPtr("jwt_vc_json"),
					},
				},
			},
			want:          nil,
			wantErr:       true,
			errorContains: "invalid-value[authorization_details.credential_definition]: not supplied",
		},
		{
			name: "Error: neither credentialFormat nor credentialConfigurationID supplied",
			args: args{
				ad: []common.AuthorizationDetails{
					{
						CredentialConfigurationId: nil,
						Locations:                 lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
						Type:                      "openid_credential",
						CredentialDefinition: &common.CredentialDefinition{
							Context: lo.ToPtr([]string{"https://example.com/context/1", "https://example.com/context/2"}),
							CredentialSubject: lo.ToPtr(map[string]interface{}{
								"key": "value",
							}),
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: nil,
					},
				},
			},
			want:    nil,
			wantErr: true,
			errorContains: "invalid-value[authorization_details.credential_configuration_id]: " +
				"neither credentialFormat nor credentialConfigurationID supplied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ValidateAuthorizationDetails(tt.args.ad)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthorizationDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && !strings.Contains(err.Error(), tt.errorContains) {
				t.Errorf("ValidateAuthorizationDetails() error = %v, errorContains %v", err, tt.errorContains)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateAuthorizationDetails() got = %v, want %v", got, tt.want)
			}
		})
	}
}
