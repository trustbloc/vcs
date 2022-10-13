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

	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

func TestService_InitiateOidcInteraction(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStorage(gomock.NewController(t))
		mockHTTPClient       = NewMockHTTPClient(gomock.NewController(t))
		credentialTemplate   = &verifiable.Credential{
			ID:     "templateID",
			Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Issuer: verifiable.Issuer{ID: "issuerID"},
		}
		issuanceReq *oidc4vc.InitiateIssuanceRequest
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID:     "txID",
					TxData: oidc4vc.TransactionData{},
				}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Body: io.NopCloser(strings.NewReader(
						`{"initiate_issuance_endpoint":"https://wallet.example.com/initiate_issuance"}`)),
					StatusCode: http.StatusOK,
				}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplate: credentialTemplate,
					ClientWellKnownURL: "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:      "https://vcs.pb.example.com/claim",
					OpState:            "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client_wellknown parameter",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID:     "txID",
					TxData: oidc4vc.TransactionData{},
				}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplate:        credentialTemplate,
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to do well-known request",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID:     "txID",
					TxData: oidc4vc.TransactionData{},
				}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("well-known request error"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplate: credentialTemplate,
					ClientWellKnownURL: "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:      "https://vcs.pb.example.com/claim",
					OpState:            "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to decode well-known config",
			setup: func() {
				mockTransactionStore.EXPECT().Store(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID:     "txID",
					TxData: oidc4vc.TransactionData{},
				}, nil)
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader("invalid json")),
					StatusCode: http.StatusOK,
				}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplate: credentialTemplate,
					ClientWellKnownURL: "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:      "https://vcs.pb.example.com/claim",
					OpState:            "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error) {
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
					CredentialTemplate:        credentialTemplate,
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceInfo, err error) {
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
				TransactionStorage: mockTransactionStore,
				HTTPClient:         mockHTTPClient,
			})
			require.NoError(t, err)

			resp, err := svc.InitiateOidcInteraction(context.TODO(), issuanceReq)
			tt.check(t, resp, err)
		})
	}
}
