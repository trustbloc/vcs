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

func TestService_AuthenticateClient(t *testing.T) {
	var (
		attestationService  *MockAttestationService
		profile             *profileapi.Issuer
		clientID            string
		clientAssertionType string
		clientAssertion     string
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = "client-id"
				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt~client-attestation-pop-jwt"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					clientID,
					"client-attestation-jwt",
				).Return(nil)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(gomock.Any(),
					clientID,
					"client-attestation-pop-jwt",
				).Return(nil)
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

				clientID = "client-id"
				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt~client-attestation-pop-jwt"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "missing client_id",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = ""

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "client_id is required")
			},
		},
		{
			name: "invalid client assertion type",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = "client-id"
				clientAssertionType = "not_supported_client_assertion_type"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "only supported client assertion type is attest_jwt_client_auth")
			},
		},
		{
			name: "invalid client assertion format",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = "client-id"
				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "invalid_assertion_format"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid client assertion format")
			},
		},
		{
			name: "fail to validate client attestation jwt",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = "client-id"
				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt~client-attestation-pop-jwt"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Return(errors.New("validate error"))

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate error")
			},
		},
		{
			name: "fail to validate client attestation pop jwt",
			setup: func() {
				profile = &profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
					},
				}

				clientID = "client-id"
				clientAssertionType = "attest_jwt_client_auth"
				clientAssertion = "client-attestation-jwt~client-attestation-pop-jwt"

				attestationService = NewMockAttestationService(gomock.NewController(t))

				attestationService.EXPECT().ValidateClientAttestationJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Return(nil)

				attestationService.EXPECT().ValidateClientAttestationPoPJWT(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
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
				AttestationService: attestationService,
			})
			require.NoError(t, err)

			err = svc.AuthenticateClient(context.Background(), profile, clientID, clientAssertionType, clientAssertion)
			tt.check(t, err)
		})
	}
}
