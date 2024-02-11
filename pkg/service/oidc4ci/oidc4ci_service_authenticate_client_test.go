/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	issuerDID = "did:oin:abc"
)

func TestService_AuthenticateClient(t *testing.T) {
	var (
		trustRegistryService *MockTrustRegistryService
		profile              *profileapi.Issuer
		clientAssertionType  string
		clientAssertion      string
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success with client attestation jwt vp",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					SigningDID: &profileapi.SigningDID{DID: issuerDID},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://policy.example.com",
						},
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))

				trustRegistryService.EXPECT().ValidateIssuance(
					context.Background(),
					profile,
					clientAssertion,
				).Times(1).Return(nil)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "attest_jwt_client_auth not supported by profile",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"none"},
					},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "policy URL not set for the profile",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "policy url not set for profile")
			},
		},
		{
			name: "client attestation not set for profile",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "client attestation not set for profile")
			},
		},
		{
			name: "invalid client assertion type",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},

					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://policy.example.com",
						},
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = "not_supported_client_assertion_type"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "only supported client assertion type is attest_jwt_client_auth")
			},
		},
		{
			name: "no client assertion type specified",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://policy.example.com",
						},
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = ""
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "no client assertion type specified")
			},
		},
		{
			name: "empty client assertion",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://policy.example.com",
						},
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = ""

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "client_assertion is required")
			},
		},
		{
			name: "fail to validate client attestation jwt",
			setup: func() {
				profile = &profileapi.Issuer{
					SigningDID: &profileapi.SigningDID{DID: issuerDID},
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://policy.example.com",
						},
						ClientAttestationCheck: profileapi.ClientAttestationCheck{
							Enabled: true,
						},
					},
				}

				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt-vp"

				trustRegistryService = NewMockTrustRegistryService(gomock.NewController(t))

				trustRegistryService.EXPECT().ValidateIssuance(
					context.Background(),
					profile,
					clientAssertion,
				).Return(errors.New("validate error"))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TrustRegistryService: trustRegistryService,
			})
			require.NoError(t, err)

			err = svc.AuthenticateClient(context.Background(), profile, clientAssertionType, clientAssertion)
			tt.check(t, err)
		})
	}
}
