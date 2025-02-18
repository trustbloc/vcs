/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
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
		expectedError error
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
			expectedError: rfc6749.
				NewInvalidRequestError(errors.New("type should be 'openid_credential'")).
				WithIncorrectValue("authorization_details.type"),
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
			expectedError: rfc6749.
				NewInvalidRequestError(
					errors.New("unsupported vc format unknown, use one of next [jwt_vc_json-ld, ldp_vc]")).
				WithIncorrectValue("authorization_details.format"),
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
			expectedError: rfc6749.
				NewInvalidRequestError(errors.New("not supplied")).
				WithIncorrectValue("authorization_details.credential_definition"),
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
			expectedError: rfc6749.NewInvalidRequestError(
				errors.New("neither credentialFormat nor credentialConfigurationID supplied")).
				WithIncorrectValue("authorization_details.credential_configuration_id"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ValidateAuthorizationDetails(tt.args.ad)
			if err != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
