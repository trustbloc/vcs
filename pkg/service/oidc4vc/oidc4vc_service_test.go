/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

func TestService_InitiateInteraction(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockHTTPClient       = NewMockHTTPClient(gomock.NewController(t))
		issuanceReq          *oidc4vc.InitiateIssuanceRequest
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						CredentialTemplate: &verifiable.Credential{
							ID: "templateID",
						},
					},
				}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Body: io.NopCloser(strings.NewReader(
						`{"initiate_issuance_endpoint":"https://wallet.example.com/initiate_issuance"}`)),
					StatusCode: http.StatusOK,
				}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Credential template ID is required",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Times(0)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateIDRequired)
			},
		},
		{
			name: "Credential template not found",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Times(0)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID3",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateNotFound)
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client well-known parameter",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to do well-known request",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("well-known request error"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to decode well-known config",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader("invalid json")),
					StatusCode: http.StatusOK,
				}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Fail to store transaction",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("store error"))
				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
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
				HTTPClient:          mockHTTPClient,
				IssuerVCSPublicHost: "https://vcs.pb.example.com/oidc",
			})
			require.NoError(t, err)

			resp, err := svc.InitiateInteraction(context.Background(), issuanceReq, &profileapi.Issuer{
				CredentialTemplates: []*verifiable.Credential{
					{
						ID:    "templateID",
						Types: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					{
						ID:    "templateID2",
						Types: []string{"VerifiableCredential", "PermanentResidentCard"},
					},
				},
			})
			tt.check(t, resp, err)
		})
	}
}

func TestService_HandlePAR(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		ad                   *oidc4vc.AuthorizationDetails
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, txID oidc4vc.TxID, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().GetByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.NoError(t, err)
				require.Equal(t, oidc4vc.TxID("txID"), txID)
			},
		},
		{
			name: "Credential type mismatch",
			setup: func() {
				mockTransactionStore.EXPECT().GetByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "NotSupportedCredentialType",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "credential type mismatch")
			},
		},
		{
			name: "Credential format mismatch",
			setup: func() {
				mockTransactionStore.EXPECT().GetByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Jwt,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "format mismatch")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4vc.NewService(&oidc4vc.Config{
				TransactionStore: mockTransactionStore,
			})
			require.NoError(t, err)

			resp, err := svc.HandlePAR(context.Background(), "opState", ad)
			tt.check(t, resp, err)
		})
	}
}
