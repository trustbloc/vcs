/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestService_PushAuthorizationDetails(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		profileSvc           = NewMockProfileService(gomock.NewController(t))
		ad                   *oidc4ci.AuthorizationDetails
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "Success AuthorizationDetails contains Format field",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "universitydegreecredential"},
					},
					Format: vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Success AuthorizationDetails contains CredentialConfigurationID field",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
				}
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(
					nil, errors.New("find tx error"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "universitydegreecredential"},
					},
					Format: vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "find tx by op state")
			},
		},
		{
			name: "Credential template not configured",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, resterr.ErrCredentialTemplateNotConfigured)
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: get profile not found",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("not found"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredential",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.ProfileNotFound, customErr.Code)
				require.Empty(t, customErr.FailedOperation)
				require.Empty(t, customErr.Component)
				require.ErrorContains(t, customErr.Err, "update tx auth details: get profile: not found")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: get profile common error",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("some error"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredential",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.SystemError, customErr.Code)
				require.Equal(t, "GetProfile", customErr.FailedOperation)
				require.Equal(t, "issuer.profile-service", customErr.Component)
				require.ErrorContains(t, customErr.Err, "update tx auth details: get profile: some error")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: empty CredentialMetaData",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: nil,
					}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredential",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.InvalidCredentialConfigurationID, customErr.Code)
				require.Empty(t, customErr.FailedOperation)
				require.Empty(t, customErr.Component)
				require.ErrorContains(t, customErr.Err, "invalid credential configuration ID")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: " +
				"CredentialMetaData for different VC type",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"PermanentResidentCardIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "PermanentResidentCard",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredential",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.InvalidCredentialConfigurationID, customErr.Code)
				require.Empty(t, customErr.FailedOperation)
				require.Empty(t, customErr.Component)
				require.ErrorContains(t, customErr.Err, "invalid credential configuration ID")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: invalid OIDC format",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJson, // <-
								},
							},
						},
					}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.CredentialFormatNotSupported, customErr.Code)
				require.Empty(t, customErr.FailedOperation)
				require.Empty(t, customErr.Component)
				require.ErrorContains(t, customErr.Err, "credential format not supported")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: Credential type not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "PermanentResidentCard",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
				}
			},
			check: func(t *testing.T, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				require.True(t, is)

				require.Equal(t, resterr.CredentialTypeNotSupported, customErr.Code)
				require.Empty(t, customErr.FailedOperation)
				require.Empty(t, customErr.Component)
				require.ErrorContains(t, customErr.Err, "credential type not supported")
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: Credential type not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "NotSupportedCredentialType"},
					},
					Format: vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, resterr.ErrCredentialTypeNotSupported)
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: Credential format not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.Jwt,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Fail to update transaction",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "update error")
			},
		},
		{
			name: "Error neither credentialFormat nor credentialConfigurationID supplied",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "neither credentialFormat nor credentialConfigurationID supplied")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileSvc,
				TransactionStore: mockTransactionStore,
			})
			require.NoError(t, err)

			err = svc.PushAuthorizationDetails(context.Background(), "opState", ad)
			tt.check(t, err)
		})
	}
}

func TestService_PrepareClaimDataAuthorizationRequest(t *testing.T) {
	var (
		req        *oidc4ci.PrepareClaimDataAuthorizationRequest
		profileSvc = NewMockProfileService(gomock.NewController(t))
	)

	tests := []struct {
		name  string
		setup func(mocks *mocks)
		check func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error)
	}{
		{
			name: "Success AuthorizationDetails contains Format field",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialDefinition: &oidc4ci.CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains CredentialConfigurationID field",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope:                []string{"openid", "profile", "address"},
						State:                oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:            "bank_issuer1",
						ProfileVersion:       "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success Scope based (AuthorizationDetails not supplied) with duplicated and unknown request scopes",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope: []string{
							"openid",
							"profile",
							"address",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
							"UniversityDegreeCredential_003",
							"UniversityDegreeCredential_004",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier_1": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_001",
								},
								"UniversityDegreeCredentialIdentifier_2": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_002",
								},
								"UniversityDegreeCredentialIdentifier_3": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_003",
								},
							},
						},
					}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope: []string{
						"UniversityDegreeCredential_001",
						"UniversityDegreeCredential_002",
						"UniversityDegreeCredential_002",
						"UniversityDegreeCredential_004",
					},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, []string{"UniversityDegreeCredential_001", "UniversityDegreeCredential_002"}, resp.Scope)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(
					nil, errors.New("find tx error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState: "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "find tx error")
				require.Nil(t, resp)
			},
		},
		{
			name: "invalid state",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid"},
						State:            oidc4ci.TransactionStateCredentialsIssued,
					},
				}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).DoAndReturn(
					expectedPublishErrorEventFunc(t,
						resterr.InvalidStateTransition,
						"unexpected transition from 5 to 3",
						"",
					),
				)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialDefinition: &oidc4ci.CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "unexpected transition from 5 to 3")
				require.Empty(t, resp)
			},
		},
		{
			name: "Response type mismatch",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						State: oidc4ci.TransactionStateIssuanceInitiated,
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						ResponseType: "code",
						Scope:        []string{"openid"},
					},
				}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					ResponseType: "invalid",
					Scope:        []string{"openid"},
					OpState:      "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorIs(t, err, resterr.ErrResponseTypeMismatch)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails supplied: request scope is unexpected",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						ResponseType: "code",
						Scope:        []string{"openid", "profile"},
						State:        oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					ResponseType: "code",
					Scope:        []string{"openid", "profile", "address"},
					OpState:      "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorIs(t, err, resterr.ErrInvalidScope)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: get profile: not found",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope: []string{
							"openid",
							"profile",
							"address",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("not found"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001", "UniversityDegreeCredential_002"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)

				var customError *resterr.CustomError
				require.ErrorAs(t, err, &customError)
				require.Equal(t, resterr.ProfileNotFound, customError.Code)
				require.Empty(t, customError.Component)
				require.Empty(t, customError.FailedOperation)
				require.ErrorContains(t, err, "check scopes: get profile: not found")
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: get profile: sustem error",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope: []string{
							"openid",
							"profile",
							"address",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("some error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001", "UniversityDegreeCredential_002"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)

				var customError *resterr.CustomError
				require.ErrorAs(t, err, &customError)
				require.Equal(t, resterr.SystemError, customError.Code)
				require.Equal(t, "GetProfile", customError.FailedOperation)
				require.Equal(t, resterr.IssuerProfileSvcComponent, customError.Component)
				require.ErrorContains(t, err, "check scopes: get profile: some error")
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: empty issuer metadata",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope: []string{
							"openid",
							"profile",
							"address",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: nil,
					}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001", "UniversityDegreeCredential_002"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)
				require.Equal(t, resterr.ErrInvalidScope, err)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: no issuer credential config with requested scope",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope: []string{
							"openid",
							"profile",
							"address",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier_3": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_003",
								},
							},
						},
					}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)
				require.Equal(t, resterr.ErrInvalidScope, err)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: invalid format",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope:                []string{"openid", "profile", "address", "UniversityDegreeCredential_001"},
						State:                oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:            "bank_issuer1",
						ProfileVersion:       "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier_3": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.LdpVC,
									Scope:  "UniversityDegreeCredential_001",
								},
							},
						},
					}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)
				require.Equal(t, resterr.ErrCredentialFormatNotSupported, err)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails not supplied: invalid type",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "PermanentResidentCard",
						},
						CredentialFormat:     vcsverifiable.Ldp,
						OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
						ResponseType:         "code",
						Scope:                []string{"openid", "profile", "address", "UniversityDegreeCredential_001"},
						State:                oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:            "bank_issuer1",
						ProfileVersion:       "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier_3": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "UniversityDegreeCredential",
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_001",
								},
							},
						},
					}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.Nil(t, resp)
				require.Equal(t, resterr.ErrCredentialTypeNotSupported, err)
			},
		},
		{
			name: "Error invalid Authorization Details",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						ResponseType: "code",
						Scope:        []string{"openid", "profile", "address"},
						State:        oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.InvalidValue,
							"neither credentialFormat nor credentialConfigurationID supplied",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "neither credentialFormat nor credentialConfigurationID supplied")
				require.Empty(t, resp)
			},
		},
		{
			name: "Error update transaction",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).DoAndReturn(
					expectedPublishErrorEventFunc(t,
						resterr.SystemError,
						"update error",
						resterr.TransactionStoreComponent,
					),
				)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialDefinition: &oidc4ci.CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "update error")
				require.Empty(t, resp)
			},
		},
		{
			name: "Error store update",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).DoAndReturn(
					expectedPublishErrorEventFunc(t,
						resterr.SystemError,
						"store update error",
						resterr.TransactionStoreComponent,
					),
				)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					Return(errors.New("store update error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialDefinition: &oidc4ci.CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "store update error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Error sending event",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationRequestPrepared)

						return errors.New("publish event")
					})

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialDefinition: &oidc4ci.CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
						Format: vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "publish event")
				require.Nil(t, resp)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mocks{
				transactionStore: NewMockTransactionStore(gomock.NewController(t)),
				eventService:     NewMockEventService(gomock.NewController(t)),
			}

			tt.setup(m)

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileSvc,
				TransactionStore: m.transactionStore,
				EventService:     m.eventService,
				EventTopic:       spi.IssuerEventTopic,
			})
			require.NoError(t, err)

			resp, err := svc.PrepareClaimDataAuthorizationRequest(context.Background(), req)
			tt.check(t, resp, err)
		})
	}
}

func TestPrepareClaimDataAuthorizationForWalletFlow(t *testing.T) {
	t.Run("invalid url", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("issuer"), "bank_issuer1").
			Return(nil, errors.New("not found"))

		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1").
			Return(nil, resterr.ErrDataNotFound)
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "wallet initiated flow get profile: not found")
	})

	t.Run("profile not found", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(nil, errors.New("not found"))
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "wallet initiated flow get profile")
	})
	t.Run("profile wallet flow not supported", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(&profileapi.Issuer{}, nil)
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "wallet initiated auth flow is not supported for current profile")
	})
	t.Run("profile wallet flow claims url missing", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(&profileapi.Issuer{
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
				},
			}, nil)
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "empty claims endpoint for profile")
	})
	t.Run("profile wallet flow credential templates are missing", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(&profileapi.Issuer{
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					ClaimsEndpoint:                   "sadsadsa",
				},
			}, nil)
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "no credential templates configured")
	})

	t.Run("profile wallet flow well-known err", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(&profileapi.Issuer{
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "123",
					},
				},
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					ClaimsEndpoint:                   "sadsadsa",
				},
			}, nil)
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		wellKnown.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("well-known err"))
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "well-known err")
	})
	t.Run("profile wallet flow event err", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), gomock.Any()).
			Return(&profileapi.Issuer{
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "123",
					},
				},
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					ClaimsEndpoint:                   "sadsadsa",
				},
			}, nil)
		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0").
			Return(nil, resterr.ErrDataNotFound)
		wellKnown.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).
			Return(&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)
		eventMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("publish err"))
		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v1.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "publish err")
	})
	t.Run("success", func(t *testing.T) {
		mockTransactionStore := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		svc, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: mockTransactionStore,
			EventService:     eventMock,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		mockTransactionStore.EXPECT().FindByOpState(gomock.Any(),
			"https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v111.0").
			Return(nil, resterr.ErrDataNotFound)
		wellKnown.EXPECT().GetOIDCConfiguration(gomock.Any(), "https://awesome.local").
			Return(&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

		eventMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, event ...*spi.Event) error {
				assert.Equal(t, "vcs-issuer", topic)
				assert.Len(t, event, 1)

				assert.Equal(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared, event[0].Type)
				return nil
			})
		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), "v111.0").
			Return(&profileapi.Issuer{
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "some-template",
					},
				},
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					IssuerWellKnownURL:               "https://awesome.local",
					ClaimsEndpoint:                   "https://awesome.claims.local",
				},
			}, nil)

		resp, err := svc.PrepareClaimDataAuthorizationRequest(context.TODO(),
			&oidc4ci.PrepareClaimDataAuthorizationRequest{
				OpState: "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v111.0",
				Scope: []string{
					"scope1",
					"scope2",
					"scope3",
				},
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Equal(t, "bank_issuer1", resp.ProfileID)
		assert.Equal(t, "v111.0", resp.ProfileVersion)
		assert.Equal(t, []string{
			"scope1",
			"scope2",
			"scope3",
		}, resp.Scope)
		assert.Equal(t, resp.Scope, *resp.WalletInitiatedFlow.Scopes)
		assert.Equal(t, "https://awesome.claims.local", resp.WalletInitiatedFlow.ClaimEndpoint)
		assert.NotEqual(t, "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer1/v111.0",
			resp.WalletInitiatedFlow.OpState)
		assert.Equal(t, "bank_issuer1", resp.WalletInitiatedFlow.ProfileId)
		assert.Equal(t, "v111.0", resp.WalletInitiatedFlow.ProfileVersion)
		assert.Equal(t, "some-template", resp.WalletInitiatedFlow.CredentialTemplateId)
	})
}

func TestValidatePreAuthCode(t *testing.T) {
	t.Run("success with pin", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		eventService := NewMockEventService(gomock.NewController(t))
		pinGenerator := NewMockPinGenerator(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
			EventService:     eventService,
			EventTopic:       spi.IssuerEventTopic,
			PinGenerator:     pinGenerator,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
			Return(&profileapi.Issuer{
				OIDCConfig: &profileapi.OIDCConfig{
					PreAuthorizedGrantAnonymousAccessSupported: true,
				},
			}, nil)

		pinGenerator.EXPECT().Validate("567", "567").Return(true)
		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				State:                oidc4ci.TransactionStateIssuanceInitiated,
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "567",
			},
		}, nil)

		eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return nil
			})

		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "567", "", "", "")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("success without pin", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return nil
			})

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("error with pin during publishing", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return errors.New("unexpected error")
			})

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(20 * time.Second)),
				UserPin:              "",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.ErrorContains(t, err, "unexpected error")
		assert.Nil(t, resp)
	})

	t.Run("invalid pin", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		pinGenerator := NewMockPinGenerator(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
			PinGenerator:     pinGenerator,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		pinGenerator.EXPECT().Validate("567", "111").Return(false)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "567",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "111", "", "", "")
		assert.ErrorContains(t, err, "invalid pin")
		assert.Nil(t, resp)
	})

	t.Run("fail to find tx", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.ErrorContains(t, err, "not found")
		assert.Nil(t, resp)
	})

	t.Run("invalid state", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "567",
				State:                oidc4ci.TransactionStateCredentialsIssued,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "567", "", "", "")
		assert.ErrorContains(t, err, "unexpected transition from 5 to 2")
		assert.Nil(t, resp)
	})

	t.Run("pin should not be provided", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "567", "", "", "")
		assert.ErrorContains(t, err, "oidc-pre-authorize-does-not-expect-pin: server does not expect pin")
		assert.Nil(t, resp)
	})

	t.Run("pin should be provided", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "123",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.ErrorContains(t, err, "oidc-pre-authorize-expect-pin: server expects user pin")
		assert.Nil(t, resp)
	})

	t.Run("get profile error", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "123",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("some error"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "123", "", "", "")
		assert.ErrorContains(t, err, "some error")
		assert.Nil(t, resp)
	})

	t.Run("issuer does not accept Token Request with a Pre-Authorized Code but without a client_id", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "123",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
			Return(&profileapi.Issuer{
				OIDCConfig: &profileapi.OIDCConfig{
					ClientID:           "clientID",
					ClientSecretHandle: "clientSecret",
					PreAuthorizedGrantAnonymousAccessSupported: false,
				},
			}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "123", "", "", "")
		assert.ErrorContains(t, err, "oidc-pre-authorize-invalid-client-id: issuer does not accept "+
			"Token Request with a Pre-Authorized Code but without a client_id")
		assert.Nil(t, resp)
	})

	t.Run("fail to authenticate client", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		trustRegistryService := NewMockTrustRegistryService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:       profileService,
			TrustRegistryService: trustRegistryService,
			TransactionStore:     storeMock,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{
			OIDCConfig: &profileapi.OIDCConfig{
				TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
			},
			Checks: profileapi.IssuanceChecks{
				Policy: profileapi.PolicyCheck{
					PolicyURL: "https://localhost/policy",
				},
				ClientAttestationCheck: profileapi.ClientAttestationCheck{
					Enabled: true,
				},
			},
		}, nil)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "client_id",
			"attest_jwt_client_auth", "")

		assert.ErrorContains(t, err, "client_assertion is required")
		assert.Nil(t, resp)
	})

	t.Run("valid pre auth code", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "12345",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "123",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "123", "", "", "")
		assert.ErrorContains(t, err, "oidc-tx-not-found: invalid pre-authorization code")
		assert.Nil(t, resp)
	})

	t.Run("error - expired pre auth code", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(-10 * time.Second)),
				UserPin:              "123",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "123", "", "", "")
		assert.ErrorContains(t, err, "oidc-tx-not-found: invalid pre-authorization code")
		assert.Nil(t, resp)
	})

	t.Run("store update error", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{}, nil)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode:          "1234",
				PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
				UserPin:              "",
				State:                oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("store update error"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.ErrorContains(t, err, "store update error")
		assert.Nil(t, resp)
	})
}

func TestService_PrepareCredential(t *testing.T) {
	var (
		httpClient *http.Client
		req        *oidc4ci.PrepareCredential
	)

	tests := []struct {
		name  string
		setup func(m *mocks)
		check func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error)
	}{
		{
			name: "Success",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						return lo.ToPtr("ackID"), nil
					})
				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
							}, nil
						},
					},
				}

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, "ackID", *resp.NotificationID)
			},
		},
		{
			name: "Success LDP",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat:    vcsverifiable.Ldp,
						CredentialExpiresAt: lo.ToPtr(time.Now().UTC().Add(55 * time.Hour)),
					},
				}, nil)

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`
				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						return lo.ToPtr("ackID"), nil
					})

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
							}, nil
						},
					},
				}

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.Equal(t, time.Now().UTC().Add(55*time.Hour).Truncate(time.Hour*24),
					resp.Credential.Contents().Expired.Time.Truncate(time.Hour*24))

				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Success LDP with name and description",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat:      vcsverifiable.Ldp,
						CredentialExpiresAt:   lo.ToPtr(time.Now().UTC().Add(55 * time.Hour)),
						CredentialName:        "awesome-credential",
						CredentialDescription: "awesome-description",
					},
				}, nil)

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`
				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						return lo.ToPtr("ackID"), nil
					})

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
							}, nil
						},
					},
				}

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.Equal(t, time.Now().UTC().Add(55*time.Hour).Truncate(time.Hour*24),
					resp.Credential.Contents().Expired.Time.Truncate(time.Hour*24))

				require.Equal(t, resp.Credential.CustomField("description"),
					"awesome-description")
				require.Equal(t, resp.Credential.CustomField("name"),
					"awesome-credential")
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Success pre-authorized flow",
			setup: func(m *mocks) {
				claimID := uuid.NewString()
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      claimID,
						CredentialFormat: vcsverifiable.Jwt,
						OrgID:            "asdasd",
						WebHookURL:       "aaaaa",
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						require.Equal(t, "asdasd", ack.OrgID)
						require.Equal(t, "aaaaa", ack.WebHookURL)

						return lo.ToPtr("ackID"), nil
					})

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				clData := &oidc4ci.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted:      []byte{0x1, 0x2, 0x3},
						EncryptedNonce: []byte{0x0, 0x2},
					},
				}

				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), claimID).Return(clData, nil)

				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						b, _ := json.Marshal(map[string]interface{}{})
						return b, nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Can not create ack",
			setup: func(m *mocks) {
				claimID := uuid.NewString()
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      claimID,
						CredentialFormat: vcsverifiable.Jwt,
						OrgID:            "asdasd",
						WebHookURL:       "aaaaa",
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("can not create ack"))

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				clData := &oidc4ci.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted:      []byte{0x1, 0x2, 0x3},
						EncryptedNonce: []byte{0x0, 0x2},
					},
				}

				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), claimID).Return(clData, nil)

				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						b, _ := json.Marshal(map[string]interface{}{})
						return b, nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Nil(t, resp.NotificationID)
			},
		},
		{
			name: "Failed to get claims for pre-authorized flow",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)

				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(nil, errors.New("get error"))

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "get claims data")
				require.Nil(t, resp)
			},
		},
		{
			name: "Failed to send event for pre-authorized flow",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					Return(lo.ToPtr("123"), nil)

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})
				clData := &oidc4ci.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted:      []byte{0x1, 0x2, 0x3},
						EncryptedNonce: []byte{0x0, 0x2},
					},
				}
				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						b, _ := json.Marshal(map[string]interface{}{})
						return b, nil
					})
				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(clData, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return errors.New("publish error")
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "publish error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Failed to update tx state",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				m.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return errors.New("store err")
					})

				clData := &oidc4ci.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted:      []byte{0x1, 0x2, 0x3},
						EncryptedNonce: []byte{0x0, 0x2},
					},
				}
				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						b, _ := json.Marshal(map[string]interface{}{})
						return b, nil
					})
				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(clData, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "store err")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(
					nil, errors.New("get error"))

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "get tx")
				require.Nil(t, resp)
			},
		},
		{
			name: "Credential template not configured",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err,
					"credential-template-not-configured: credential template not configured")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to make request to claim endpoint",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							return &http.Response{}, errors.New("http error")
						},
					},
				}

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "http error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Claim endpoint returned other than 200 OK status code",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusInternalServerError,
								Body:       io.NopCloser(bytes.NewBuffer(nil)),
							}, nil
						},
					},
				}

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "claim endpoint returned status code")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to read response body from claim endpoint when status is not 200 OK",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusInternalServerError,
								Body:       io.NopCloser(&failReader{}),
							}, nil
						},
					},
				}

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "claim endpoint returned status code")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to decode claim data",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewBuffer([]byte("invalid"))),
							}, nil
						},
					},
				}

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "/oidc/idp//",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "decode claim data")
				require.Nil(t, resp)
			},
		},
		{
			name: "Invalid audience claim",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				m.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`

				httpClient = &http.Client{
					Transport: &mockTransport{
						func(req *http.Request) (*http.Response, error) {
							assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
							}, nil
						},
					},
				}

				req = &oidc4ci.PrepareCredential{
					TxID:          "txID",
					AudienceClaim: "invalid",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "invalid aud")
				require.Nil(t, resp)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mocks{
				transactionStore: NewMockTransactionStore(gomock.NewController(t)),
				claimDataStore:   NewMockClaimDataStore(gomock.NewController(t)),
				eventService:     NewMockEventService(gomock.NewController(t)),
				crypto:           NewMockDataProtector(gomock.NewController(t)),
				ackService:       NewMockAckService(gomock.NewController(t)),
			}

			tt.setup(m)

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore: m.transactionStore,
				ClaimDataStore:   m.claimDataStore,
				HTTPClient:       httpClient,
				EventService:     m.eventService,
				EventTopic:       spi.IssuerEventTopic,
				DataProtector:    m.crypto,
				AckService:       m.ackService,
			})
			require.NoError(t, err)

			resp, err := svc.PrepareCredential(context.Background(), req)
			tt.check(t, resp, err)
		})
	}
}

func TestSelectProperFormat(t *testing.T) {
	srv, err := oidc4ci.NewService(&oidc4ci.Config{})
	assert.NoError(t, err)

	t.Run("ldp", func(t *testing.T) {
		assert.Equal(t, vcsverifiable.LdpVC, srv.SelectProperOIDCFormat(vcsverifiable.Ldp, nil))
	})

	t.Run("strict", func(t *testing.T) {
		assert.Equal(t, vcsverifiable.JwtVCJsonLD, srv.SelectProperOIDCFormat(vcsverifiable.Jwt,
			&profileapi.CredentialTemplate{
				Checks: profileapi.CredentialTemplateChecks{
					Strict: true,
				},
			}))
	})

	t.Run("strict", func(t *testing.T) {
		assert.Equal(t, vcsverifiable.JwtVCJson, srv.SelectProperOIDCFormat(vcsverifiable.Jwt,
			&profileapi.CredentialTemplate{}))
	})
}

func TestExtractNoScope(t *testing.T) {
	assert.Equal(t, "", oidc4ci.ExtractIssuerURL("scope1"))
}

type failReader struct{}

func (f *failReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

type eventPublishFunc func(ctx context.Context, topic string, messages ...*spi.Event) error

func expectedPublishEventFunc(
	t *testing.T,
	eventType spi.EventType,
) eventPublishFunc {
	t.Helper()

	return func(ctx context.Context, topic string, messages ...*spi.Event) error {
		require.Len(t, messages, 1)
		require.Equal(t, eventType, messages[0].Type)

		return nil
	}
}

func expectedPublishErrorEventFunc(
	t *testing.T,
	errCode resterr.ErrorCode,
	errMessage string,
	errComponent resterr.Component,
) eventPublishFunc {
	t.Helper()

	return func(ctx context.Context, topic string, messages ...*spi.Event) error {
		require.Len(t, messages, 1)
		require.Equal(t, spi.IssuerOIDCInteractionFailed, messages[0].Type)

		var ep oidc4ci.EventPayload

		jsonData, err := json.Marshal(messages[0].Data.(map[string]interface{}))
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(jsonData, &ep))

		assert.Equalf(t, string(errCode), ep.ErrorCode, "unexpected error code")
		assert.Equalf(t, errComponent, ep.ErrorComponent, "unexpected error component")

		if errMessage != "" {
			assert.Containsf(t, ep.Error, errMessage, "unexpected error message")
		}

		return nil
	}
}
