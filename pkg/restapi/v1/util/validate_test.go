/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestValidateAuthorizationDetails(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tests := []struct {
			name string
			arg  *string
			want vcsverifiable.Format
		}{
			{
				name: "ldp_vc format",
				arg:  lo.ToPtr(string(common.LdpVc)),
				want: vcsverifiable.Ldp,
			},
			{
				name: "jwt_vc format",
				arg:  lo.ToPtr(string(common.JwtVcJsonLd)),
				want: vcsverifiable.Jwt,
			},
			{
				name: "no format",
				arg:  nil,
				want: "",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ad := &common.AuthorizationDetails{
					Type:      "openid_credential",
					Types:     []string{"VerifiableCredential", "UniversityDegreeCredential"},
					Format:    tt.arg,
					Locations: lo.ToPtr([]string{"https://example.com/rs1", "https://example.com/rs2"}),
				}

				got, err := util.ValidateAuthorizationDetails(ad)
				require.NoError(t, err)
				require.Equal(t, &oidc4ci.AuthorizationDetails{
					Type:      "openid_credential",
					Types:     []string{"VerifiableCredential", "UniversityDegreeCredential"},
					Format:    tt.want,
					Locations: []string{"https://example.com/rs1", "https://example.com/rs2"},
				}, got)
			})
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		ad := &common.AuthorizationDetails{
			Type:   "openid_credential",
			Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Format: lo.ToPtr("invalid"),
		}

		got, err := util.ValidateAuthorizationDetails(ad)
		require.ErrorContains(t, err, "unsupported vc format")
		require.Nil(t, got)
	})

	t.Run("type should be 'openid_credential'", func(t *testing.T) {
		ad := &common.AuthorizationDetails{
			Type:   "invalid",
			Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Format: lo.ToPtr("ldp_vc"),
		}

		got, err := util.ValidateAuthorizationDetails(ad)
		require.ErrorContains(t, err, "type should be 'openid_credential'")
		require.Nil(t, got)
	})
}
