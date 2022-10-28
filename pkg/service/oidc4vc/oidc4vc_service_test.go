/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

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
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
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
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
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
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
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

func TestService_PrepareClaimDataAuthorizationRequest(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		req                  *oidc4vc.PrepareClaimDataAuthorizationRequest
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4vc.PrepareClaimDataAuthorizationResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				req = &oidc4vc.PrepareClaimDataAuthorizationRequest{
					OpState: "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.PrepareClaimDataAuthorizationResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Fail to get transaction by opState",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(
					nil, errors.New("store error"))

				req = &oidc4vc.PrepareClaimDataAuthorizationRequest{
					OpState: "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "store error")
				require.Nil(t, resp)
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

			resp, err := svc.PrepareClaimDataAuthorizationRequest(context.Background(), req)
			tt.check(t, resp, err)
		})
	}
}
