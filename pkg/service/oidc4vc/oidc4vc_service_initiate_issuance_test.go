/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

const (
	issuerWellKnownURL  = "https://issuer.example.com/.well-known/openid-configuration"
	walletWellKnownURL  = "https://wallet.example.com/.well-known/openid-configuration"
	issuerVCSPublicHost = "https://vcs.pb.example.com/oidc"
)

//go:embed testdata/issuer_profile.json
var profileJSON []byte

func TestService_InitiateIssuance(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockWellKnownService = NewMockWellKnownService(gomock.NewController(t))
		issuanceReq          *oidc4vc.InitiateIssuanceRequest
		profile              *profileapi.Issuer
	)

	var testProfile profileapi.Issuer
	require.NoError(t, json.Unmarshal(profileJSON, &testProfile))

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&oidc4vc.Transaction{
						ID: "txID",
						TransactionData: oidc4vc.TransactionData{
							CredentialTemplate: &profileapi.CredentialTemplate{
								ID: "templateID",
							},
						},
					}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4vc.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4vc.OIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Profile is not active",
			setup: func() {
				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     false,
					OIDCConfig: &profileapi.OIDC4VCConfig{},
					VCConfig:   &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrProfileNotActive)
			},
		},
		{
			name: "OIDC4VC authorized code flow not supported",
			setup: func() {
				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:   true,
					VCConfig: &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrAuthorizedCodeFlowNotSupported)
			},
		},
		{
			name: "VC options not configured",
			setup: func() {
				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDC4VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrVCOptionsNotConfigured)
			},
		},
		{
			name: "Credential template not configured",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDC4VCConfig{},
					VCConfig:   &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateNotConfigured)
			},
		},
		{
			name: "Credential template ID is required",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateIDRequired)
			},
		},
		{
			name: "Credential template not found",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID3",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateNotFound)
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client well-known parameter",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4vc.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        walletWellKnownURL,
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to do well-known request",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&oidc4vc.Transaction{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4vc.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					nil, errors.New("invalid json"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Fail to get OIDC configuration",
			setup: func() {
				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					nil, errors.New("well known service error"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "get oidc configuration from well-known")
			},
		},
		{
			name: "Fail to store transaction",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					nil, fmt.Errorf("store error"))

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4vc.OIDCConfiguration{}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "store error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4vc.NewService(&oidc4vc.Config{
				TransactionStore:    mockTransactionStore,
				WellKnownService:    mockWellKnownService,
				IssuerVCSPublicHost: issuerVCSPublicHost,
			})
			require.NoError(t, err)

			resp, err := svc.InitiateIssuance(context.Background(), issuanceReq, profile)
			tt.check(t, resp, err)
		})
	}
}
