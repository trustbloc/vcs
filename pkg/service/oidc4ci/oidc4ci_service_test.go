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
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
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
				prcUUID, udUUID := uuid.NewString(), uuid.NewString()

				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredentialID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "PermanentResidentCardID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // only single CredentialConfiguration expected.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredentialID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}).Return(nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{},
						},
					}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.JwtVCJsonLD,
				}
			},
			check: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Success AuthorizationDetails contains CredentialConfigurationID field",
			setup: func() {
				prcUUID, udUUID := uuid.NewString(), uuid.NewString()

				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredentialID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "PermanentResidentCardID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
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

				mockTransactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // only single CredentialConfiguration expected.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredentialID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}).Return(nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
				}
			},
			check: func(t *testing.T, err error) {
				assert.NoError(t, err)
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
					Format: vcsverifiable.JwtVCJsonLD,
				}
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "find tx by op state")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: get profile not found",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.ProfileNotFound, customErr.Code)
				assert.Empty(t, customErr.FailedOperation)
				assert.Empty(t, customErr.Component)
				assert.ErrorContains(t, customErr.Err, "not found")
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: get profile common error",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.SystemError, customErr.Code)
				assert.Equal(t, "GetProfile", customErr.FailedOperation)
				assert.Equal(t, "issuer.profile-service", customErr.Component)
				assert.ErrorContains(t, customErr.Err, "some error")
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
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.InvalidCredentialConfigurationID, customErr.Code)
				assert.Empty(t, customErr.FailedOperation)
				assert.Empty(t, customErr.Component)
				assert.ErrorContains(t, customErr.Err, "invalid credential configuration ID")
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
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.InvalidCredentialConfigurationID, customErr.Code)
				assert.Empty(t, customErr.FailedOperation)
				assert.Empty(t, customErr.Component)
				assert.ErrorContains(t, customErr.Err, "invalid credential configuration ID")
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
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.CredentialFormatNotSupported, customErr.Code)
				assert.Empty(t, customErr.FailedOperation)
				assert.Empty(t, customErr.Component)
				assert.ErrorContains(t, customErr.Err, "credential format not supported")
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
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
				assert.True(t, is)

				assert.Equal(t, resterr.CredentialTypeNotSupported, customErr.Code)
				assert.Empty(t, customErr.FailedOperation)
				assert.Empty(t, customErr.Component)
				assert.ErrorContains(t, customErr.Err, "credential type not supported")
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: Credential format not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.JwtVCJsonLD,
				}
			},
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Fail to update transaction",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

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
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Format: vcsverifiable.JwtVCJsonLD,
				}
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "update error")
			},
		},
		{
			name: "Error neither credentialFormat nor credentialConfigurationID supplied",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
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
					CredentialDefinition: &oidc4ci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
				}
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "neither credentialFormat nor credentialConfigurationID supplied")
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
			assert.NoError(t, err)

			err = svc.PushAuthorizationDetails(context.Background(), "opState", []*oidc4ci.AuthorizationDetails{ad})
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
		// Success.
		{
			name: "Success AuthorizationDetails contains duplicated Format field - same credential with different type",
			setup: func(mocks *mocks) {
				prcUUID, udUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect only single CredentialConfiguration.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
						Checks:             profileapi.IssuanceChecks{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains duplicated Format field - same credential with same type",
			setup: func(mocks *mocks) {
				udUUID1, udUUID2 := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect 2 CredentialConfigurations.
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
							{
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
						Checks:             profileapi.IssuanceChecks{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains either Format and " +
				"CredentialConfigurationID field - different credentials",
			setup: func(mocks *mocks) {
				prcUUID, udUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect UniversityDegreeCredentialIdentifier CredentialConfiguration.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{ // Expect PermanentResidentCardIdentifier CredentialConfiguration.
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialConfigurationID: "PermanentResidentCardIdentifier",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
						{
							CredentialConfigurationID: "PermanentResidentCardIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains either Format and CredentialConfigurationID field: " +
				"Same credentials: case 1 of order of AuthorizationDetails in reqeust",
			setup: func(mocks *mocks) {
				udUUID, prcUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect only PermanentResidentCardIdentifier CredentialConfiguration.
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field.
									CredentialConfigurationID: "PermanentResidentCardIdentifier",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "PermanentResidentCard"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
						{
							CredentialConfigurationID: "PermanentResidentCardIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains either Format and CredentialConfigurationID field: " +
				"Same credentials: case 2 of order of AuthorizationDetails in reqeust",
			setup: func(mocks *mocks) {
				udUUID, prcUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect only PermanentResidentCardIdentifier CredentialConfiguration.
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{
									Format: vcsverifiable.JwtVCJsonLD,
									CredentialDefinition: &oidc4ci.CredentialDefinition{
										Type: []string{"VerifiableCredential", "PermanentResidentCard"},
									},
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "PermanentResidentCardIdentifier",
						},
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "PermanentResidentCard"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains duplicated CredentialConfigurationID field - " +
				"single credential",
			setup: func(mocks *mocks) {
				prcUUID, udUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile", "address"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect single CredentialConfiguration.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}).
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
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success AuthorizationDetails contains duplicated CredentialConfigurationID field - " +
				"multiple credentials with same type",
			setup: func(mocks *mocks) {
				udUUID1, udUUID2 := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile", "address"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect 2 CredentialConfigurations.
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
							{ // Expect 2 CredentialConfigurations.
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}).
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
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"openid", "profile"}, resp.Scope)
			},
		},
		{
			name: "Success Scope based (AuthorizationDetails not supplied) with duplicated and unknown request scopes",
			setup: func(mocks *mocks) {
				udUUID1, udUUID2, udUUID3 := uuid.NewString(), uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
							"UniversityDegreeCredential_001",
							"UniversityDegreeCredential_002",
							"UniversityDegreeCredential_003",
							"UniversityDegreeCredential_004",
							"UniversityDegreeCredential_005",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
							{
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_2",
							},
							{
								ID:                   udUUID3,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_3",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
								"UniversityDegreeCredential_002",
								"UniversityDegreeCredential_003",
							},
						},
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

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"UniversityDegreeCredential_001", // expect only valid scopes.
							"UniversityDegreeCredential_002",
						},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{ // expect 2 CredentialConfigurations.
							{ // do not expect AuthorizationDetails.
								ID:                   udUUID1,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
							{ // do not expect AuthorizationDetails.
								ID:                   udUUID2,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_2",
							},
						},
					},
				}).
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
						"UniversityDegreeCredential_001", // requested.
						"UniversityDegreeCredential_002", // requested.
						"UniversityDegreeCredential_002", // ignored.
						"UniversityDegreeCredential_004", // not supported by profile.
						"UniversityDegreeCredential_005", // tx does not contain TxCredentialConfiguration with given scope.
					},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"UniversityDegreeCredential_001", "UniversityDegreeCredential_002"}, resp.Scope)
			},
		},
		{
			name: "Success Scope based (AuthorizationDetails not supplied) with format mismatch",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
							"UniversityDegreeCredential_001",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC, // Error cause.
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
							},
						},
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
							},
						},
					}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"UniversityDegreeCredential_001", // expect only valid scopes.
						},
						State:                   oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:               "bank_issuer1",
						ProfileVersion:          "v1.0",
						CredentialConfiguration: nil,
					},
				}).
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
					},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"UniversityDegreeCredential_001"}, resp.Scope)
			},
		},
		{
			name: "Success Scope based (AuthorizationDetails not supplied) with type mismatch",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
							"UniversityDegreeCredential_001",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "UniversityDegreeCredential",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
							},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier_1": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{
											"VerifiableCredential", "PermanentResidentCard", // invalid configuration.
										},
									},
									Format: vcsverifiable.JwtVCJsonLD,
									Scope:  "UniversityDegreeCredential_001",
								},
							},
						},
					}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"UniversityDegreeCredential_001", // expect only valid scopes.
						},
						State:                   oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:               "bank_issuer1",
						ProfileVersion:          "v1.0",
						CredentialConfiguration: nil,
					},
				}).
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
					},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"UniversityDegreeCredential_001"}, resp.Scope)
			},
		},
		{
			name: "Success Scope and AuthorizationDetails based - different credentials",
			setup: func(mocks *mocks) {
				udUUID, prcUUID := uuid.NewString(), uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
							"UniversityDegreeCredential_001",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID1",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID2",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier_2",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
							},
						},
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
								"PermanentResidentCardIdentifier_2": {
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

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"UniversityDegreeCredential_001", // expect only valid scopes.
						},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Do not expect AuthorizationDetails.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID1",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
							{
								ID:                   prcUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID2",
									Type: "PermanentResidentCard",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{
									CredentialConfigurationID: "PermanentResidentCardIdentifier_2",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier_2",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "PermanentResidentCardIdentifier_2",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"UniversityDegreeCredential_001"}, resp.Scope)
			},
		},
		{
			name: "Success Scope and AuthorizationDetails based - same credentials",
			setup: func(mocks *mocks) {
				udUUID := uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
							"UniversityDegreeCredential_001",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID1",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
							},
						},
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
							},
						},
					}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"UniversityDegreeCredential_001", // expect only valid scopes.
						},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Do not expect AuthorizationDetails.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "TemplateID1",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(expectedPublishEventFunc(t, spi.IssuerOIDCInteractionAuthorizationRequestPrepared))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier_1",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, []string{"UniversityDegreeCredential_001"}, resp.Scope)
			},
		},
		// Errors.
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
				assert.ErrorContains(t, err, "find tx error")
				assert.Nil(t, resp)
			},
		},
		{
			name: "invalid tx state",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						State: oidc4ci.TransactionStateCredentialsIssued,
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
					OpState: "opState",
					Scope:   []string{"openid"},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.ErrorContains(t, err, "unexpected transition from 5 to 3")
				assert.Empty(t, resp)
			},
		},
		{
			name: "Response type mismatch",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						State:        oidc4ci.TransactionStateIssuanceInitiated,
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
				assert.ErrorIs(t, err, resterr.ErrResponseTypeMismatch)
			},
		},
		{
			name: "Error invalid scope: AuthorizationDetails supplied: request scope is unexpected",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID: uuid.NewString(),
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.InvalidScope,
							"invalid scope",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					ResponseType: "code",
					Scope:        []string{"openid", "profile", "address"},
					OpState:      "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.ErrorIs(t, err, resterr.ErrInvalidScope)
			},
		},
		{
			name: "get profile: not found",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("not found"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)

				var customError *resterr.CustomError
				assert.ErrorAs(t, err, &customError)
				assert.Equal(t, resterr.ProfileNotFound, customError.Code)
				assert.Empty(t, customError.Component)
				assert.Empty(t, customError.FailedOperation)
				assert.ErrorContains(t, err, "get profile: not found")
			},
		},
		{
			name: "get profile: system error",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					nil, errors.New("some error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)

				var customError *resterr.CustomError
				assert.ErrorAs(t, err, &customError)
				assert.Equal(t, resterr.SystemError, customError.Code)
				assert.Equal(t, "GetProfile", customError.FailedOperation)
				assert.Equal(t, resterr.IssuerProfileSvcComponent, customError.Component)
				assert.ErrorContains(t, err, "get profile: some error")
			},
		},
		// Ad errors.
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: " +
				"empty profile.CredentialMetaData: resterr.ErrInvalidCredentialConfigurationID",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: nil, // error cause.
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.InvalidCredentialConfigurationID,
							"invalid credential configuration ID",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrInvalidCredentialConfigurationID)
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: " +
				"format mismatch: resterr.ErrCredentialFormatNotSupported",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC, // error cause.
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
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

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialFormatNotSupported,
							"credential format not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: " +
				"empty meta credential definition: resterr.ErrCredentialTypeNotSupported",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: nil, // error cause
									Format:               vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialTypeNotSupported,
							"credential type not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialTypeNotSupported)
			},
		},
		{
			name: "Error AuthorizationDetails contains CredentialConfigurationID field: " +
				"CredentialDefinition.Type mismatch: resterr.ErrCredentialTypeNotSupported",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{
							CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
								"UniversityDegreeCredentialIdentifier": {
									CredentialDefinition: &profileapi.CredentialDefinition{
										Type: []string{"VerifiableCredentials", "PermanentResidentCard"},
									},
									Format: vcsverifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialTypeNotSupported,
							"credential type not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialTypeNotSupported)
			},
		},

		{
			name: "Error AuthorizationDetails contains duplicated CredentialConfigurationID field: " +
				"txCredentialConfiguration is not fund with given CredentialConfigurationID",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile", "address"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.InvalidCredentialConfigurationID,
							"invalid credential configuration ID",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "PermanentResidentCardIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrInvalidCredentialConfigurationID)
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: no txCredentialConfigurations: " +
				"requested credential format is not valid",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:               "bank_issuer1",
						ProfileVersion:          "v1.0",
						ResponseType:            "code",
						Scope:                   []string{"openid", "profile"},
						State:                   oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialFormatNotSupported,
							"credential format not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: CredentialTemplate.Type mismatch: " +
				"requested credential format is not valid",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialFormatNotSupported,
							"credential format not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Error AuthorizationDetails contains Format field: txCredentialConfig.OIDCCredentialFormat mismatch: " +
				"requested credential format is not valid",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC, // cause of mismatch.
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.CredentialFormatNotSupported,
							"credential format not supported",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, resterr.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Error invalid Authorization Details: neither credentialFormat nor credentialConfigurationID supplied",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile", "address"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "ConfigurationID",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
								"UniversityDegreeCredential_001",
							},
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
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{{}},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.ErrorContains(t, err, "neither credentialFormat nor credentialConfigurationID supplied")
				assert.Empty(t, resp)
			},
		},
		// Scope errors.
		{
			name: "Error Scope based: scope is not in tx",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType: "code",
						Scope: []string{
							"openid",
							"profile",
						},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{
								"openid",
								"profile",
							},
						},
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.InvalidScope,
							"invalid scope",
							"",
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:              "opState",
					ResponseType:         "code",
					Scope:                []string{"UniversityDegreeCredential_001"},
					AuthorizationDetails: nil,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.Nil(t, resp)
				assert.Equal(t, resterr.ErrInvalidScope, err)
			},
		},
		// Rest errors.
		{
			name: "Error tx store update",
			setup: func(mocks *mocks) {
				udUUID := uuid.NewString()
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile", "address"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
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

				mocks.transactionStore.EXPECT().Update(gomock.Any(), &oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{ // Expect single CredentialConfiguration.
								ID:                   udUUID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "templateID",
									Type: "UniversityDegreeCredential",
								},
								AuthorizationDetails: &oidc4ci.AuthorizationDetails{ // Expect AuthorizationDetails field
									CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)

						return errors.New("some error")
					}).Times(1)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(
						expectedPublishErrorEventFunc(t,
							resterr.SystemError,
							"some error",
							resterr.TransactionStoreComponent,
						))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				var customErr *resterr.CustomError
				is := errors.As(err, &customErr)
				assert.True(t, is)

				assert.Equal(t, resterr.SystemError, customErr.Code)
				assert.Equal(t, "Update", customErr.FailedOperation)
				assert.Equal(t, "transaction-store", customErr.Component)
				assert.ErrorContains(t, customErr.Err, "some error")
			},
		},
		{
			name: "Error sending event",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						ProfileID:      "bank_issuer1",
						ProfileVersion: "v1.0",
						ResponseType:   "code",
						Scope:          []string{"openid", "profile"},
						State:          oidc4ci.TransactionStateIssuanceInitiated,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "credetnialTempalteID",
									Type: "UniversityDegreeCredential",
								},
								CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
							},
						},
					},
				}, nil)

				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(1)

				profileSvc.EXPECT().GetProfile("bank_issuer1", "v1.0").Return(
					&profileapi.Issuer{
						Active: true,
						OIDCConfig: &profileapi.OIDCConfig{
							ScopesSupported: []string{"openid", "profile", "address"},
						},
						CredentialMetaData: &profileapi.CredentialMetaData{},
					}, nil)

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
					AuthorizationDetails: []*oidc4ci.AuthorizationDetails{
						{
							CredentialDefinition: &oidc4ci.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Format: vcsverifiable.JwtVCJsonLD,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				assert.ErrorContains(t, err, "publish event")
				assert.Nil(t, resp)
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
			assert.NoError(t, err)

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
		assert.ErrorContains(t, err, "profile-not-found: not found")
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
		assert.ErrorContains(t, err, "profile-not-found: not found")
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
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				PreAuthCode: "1234",
				UserPin:     "567",
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("success with policy check", func(t *testing.T) {
		profileService := NewMockProfileService(gomock.NewController(t))
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		trustRegistry := NewMockTrustRegistry(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			ProfileService:   profileService,
			TrustRegistry:    trustRegistry,
			TransactionStore: storeMock,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
			Return(&profileapi.Issuer{
				OIDCConfig: &profileapi.OIDCConfig{
					PreAuthorizedGrantAnonymousAccessSupported: true,
					TokenEndpointAuthMethodsSupported:          []string{"attest_jwt_client_auth"},
				},
				Checks: profileapi.IssuanceChecks{
					Policy: profileapi.PolicyCheck{
						PolicyURL: "https://localhost/policy",
					},
				},
			}, nil)

		trustRegistry.EXPECT().ValidateIssuance(gomock.Any(), gomock.Any(),
			&trustregistry.ValidateIssuanceData{
				AttestationVP:   "attestation_vp_jwt",
				CredentialTypes: []string{"UniversityDegreeCredential"},
				Nonce:           "1234",
			},
		).Return(nil)

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return nil
			})

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialConfigurationID: "ConfigurationID",
					},
				},
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "attest_jwt_client_auth",
			"attestation_vp_jwt")
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
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(20 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "567",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "567",
				State:       oidc4ci.TransactionStateCredentialsIssued,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "123",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "123",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "123",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "12345",
				UserPin:     "123",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "123",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(-10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
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
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
					{
						PreAuthCodeExpiresAt:      lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
						CredentialConfigurationID: "ConfigurationID",
					},
				},
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("store update error"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "")
		assert.ErrorContains(t, err, "store update error")
		assert.Nil(t, resp)
	})

	t.Run("check policy failure", func(t *testing.T) {
		t.Run("no client assertion type specified", func(t *testing.T) {
			profileService := NewMockProfileService(gomock.NewController(t))
			storeMock := NewMockTransactionStore(gomock.NewController(t))
			trustRegistry := NewMockTrustRegistry(gomock.NewController(t))

			srv, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileService,
				TrustRegistry:    trustRegistry,
				TransactionStore: storeMock,
			})
			assert.NoError(t, err)

			profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
				Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						PreAuthorizedGrantAnonymousAccessSupported: true,
						TokenEndpointAuthMethodsSupported:          []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://localhost/policy",
						},
					},
				}, nil)

			trustRegistry.EXPECT().ValidateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					PreAuthCode: "1234",
					UserPin:     "",
					State:       oidc4ci.TransactionStateIssuanceInitiated,
					CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
						{
							PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
							CredentialTemplate: &profileapi.CredentialTemplate{
								Type: "UniversityDegreeCredential",
							},
							CredentialConfigurationID: "ConfigurationID",
						},
					},
				},
			}, nil)

			resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "", "attestation_vp_jwt")
			assert.ErrorContains(t, err, "no client assertion type specified")
			assert.Nil(t, resp)
		})
		t.Run("only supported client assertion type is attest_jwt_client_auth", func(t *testing.T) {
			profileService := NewMockProfileService(gomock.NewController(t))
			storeMock := NewMockTransactionStore(gomock.NewController(t))
			trustRegistry := NewMockTrustRegistry(gomock.NewController(t))

			srv, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileService,
				TrustRegistry:    trustRegistry,
				TransactionStore: storeMock,
			})
			assert.NoError(t, err)

			profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
				Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						PreAuthorizedGrantAnonymousAccessSupported: true,
						TokenEndpointAuthMethodsSupported:          []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://localhost/policy",
						},
					},
				}, nil)

			trustRegistry.EXPECT().ValidateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					PreAuthCode: "1234",
					UserPin:     "",
					State:       oidc4ci.TransactionStateIssuanceInitiated,
					CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
						{
							PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
							CredentialTemplate: &profileapi.CredentialTemplate{
								Type: "UniversityDegreeCredential",
							},
							CredentialConfigurationID: "ConfigurationID",
						},
					},
				},
			}, nil)

			resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "invalid_assertion_type",
				"attestation_vp_jwt")
			assert.ErrorContains(t, err, "only supported client assertion type is attest_jwt_client_auth")
			assert.Nil(t, resp)
		})
		t.Run("client_assertion is required", func(t *testing.T) {
			profileService := NewMockProfileService(gomock.NewController(t))
			storeMock := NewMockTransactionStore(gomock.NewController(t))
			trustRegistry := NewMockTrustRegistry(gomock.NewController(t))

			srv, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileService,
				TrustRegistry:    trustRegistry,
				TransactionStore: storeMock,
			})
			assert.NoError(t, err)

			profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
				Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						PreAuthorizedGrantAnonymousAccessSupported: true,
						TokenEndpointAuthMethodsSupported:          []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://localhost/policy",
						},
					},
				}, nil)

			trustRegistry.EXPECT().ValidateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					PreAuthCode: "1234",
					UserPin:     "",
					State:       oidc4ci.TransactionStateIssuanceInitiated,
					CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
						{
							PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
							CredentialTemplate: &profileapi.CredentialTemplate{
								Type: "UniversityDegreeCredential",
							},
							CredentialConfigurationID: "ConfigurationID",
						},
					},
				},
			}, nil)

			resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "attest_jwt_client_auth",
				"")
			assert.ErrorContains(t, err, "client_assertion is required")
			assert.Nil(t, resp)
		})
		t.Run("validate issuance error", func(t *testing.T) {
			profileService := NewMockProfileService(gomock.NewController(t))
			storeMock := NewMockTransactionStore(gomock.NewController(t))
			trustRegistry := NewMockTrustRegistry(gomock.NewController(t))

			srv, err := oidc4ci.NewService(&oidc4ci.Config{
				ProfileService:   profileService,
				TrustRegistry:    trustRegistry,
				TransactionStore: storeMock,
			})
			assert.NoError(t, err)

			profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
				Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						PreAuthorizedGrantAnonymousAccessSupported: true,
						TokenEndpointAuthMethodsSupported:          []string{"attest_jwt_client_auth"},
					},
					Checks: profileapi.IssuanceChecks{
						Policy: profileapi.PolicyCheck{
							PolicyURL: "https://localhost/policy",
						},
					},
				}, nil)

			trustRegistry.EXPECT().ValidateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(errors.New("validate issuance error"))

			storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					PreAuthCode: "1234",
					UserPin:     "",
					State:       oidc4ci.TransactionStateIssuanceInitiated,
					CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
						{
							PreAuthCodeExpiresAt: lo.ToPtr(time.Now().UTC().Add(10 * time.Second)),
							CredentialTemplate: &profileapi.CredentialTemplate{
								Type: "UniversityDegreeCredential",
							},
							CredentialConfigurationID: "ConfigurationID",
						},
					},
				},
			}, nil)

			resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "", "", "attest_jwt_client_auth",
				"attestation_vp_jwt")
			assert.ErrorContains(t, err, "oidc-client-authentication-failed: validate issuance error")
			assert.Nil(t, resp)
		})
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
			name: "Success multiple credentials different type",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).Times(2).
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"PermanentResidentCard"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				assert.Len(t, resp.Credentials, 2)
				vc1 := resp.Credentials[0]

				assert.NotEmpty(t, vc1.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "VerifiedEmployee"}, vc1.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc1.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc1.OidcFormat)
				assert.NotEmpty(t, vc1.CredentialTemplate)
				assert.Equal(t, "ackID", *vc1.NotificationID)

				vc2 := resp.Credentials[1]
				assert.NotEmpty(t, vc2.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "PermanentResidentCard"}, vc2.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc2.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc2.OidcFormat)
				assert.NotEmpty(t, vc2.CredentialTemplate)
				assert.Equal(t, "ackID", *vc2.NotificationID)
			},
		},
		{
			name: "Success multiple credentials same type",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).Times(2).
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				assert.Len(t, resp.Credentials, 2)
				vc1 := resp.Credentials[0]

				assert.NotEmpty(t, vc1.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "VerifiedEmployee"}, vc1.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc1.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc1.OidcFormat)
				assert.NotEmpty(t, vc1.CredentialTemplate)
				assert.Equal(t, "ackID", *vc1.NotificationID)

				vc2 := resp.Credentials[1]
				assert.NotEmpty(t, vc2.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "VerifiedEmployee"}, vc2.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc2.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc2.OidcFormat)
				assert.NotEmpty(t, vc2.CredentialTemplate)
				assert.Equal(t, "ackID", *vc2.NotificationID)
			},
		},
		{
			name: "Success LDP",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialExpiresAt:       lo.ToPtr(time.Now().UTC().Add(55 * time.Hour)),
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.LdpVC,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.Equal(t, time.Now().UTC().Add(55*time.Hour).Truncate(time.Hour*24),
					resp.Credentials[0].Credential.Contents().Expired.Time.Truncate(time.Hour*24))

				assert.NoError(t, err)
				assert.NotNil(t, resp)
			},
		},
		{
			name: "Success LDP with name and description",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.LdpVC,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialName:            "awesome-credential",
								CredentialDescription:     "awesome-description",
								CredentialExpiresAt:       lo.ToPtr(time.Now().UTC().Add(55 * time.Hour)),
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.LdpVC,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.Equal(t, time.Now().UTC().Add(55*time.Hour).Truncate(time.Hour*24),
					resp.Credentials[0].Credential.Contents().Expired.Time.Truncate(time.Hour*24))

				assert.Equal(t, resp.Credentials[0].Credential.CustomField("description"),
					"awesome-description")
				assert.Equal(t, resp.Credentials[0].Credential.CustomField("name"),
					"awesome-credential")
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			},
		},
		{
			name: "Success pre-authorized flow - multiple credentials different type",
			setup: func(m *mocks) {
				claimID := uuid.NewString()
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IsPreAuthFlow: true,
						OrgID:         "asdasd",
						WebHookURL:    "aaaaa",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          claimID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          claimID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "PermanentResidentCard",
								},
								CredentialConfigurationID: "PermanentResidentCardIdentifier",
							},
						},
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).Times(2).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						assert.Equal(t, "asdasd", ack.OrgID)
						assert.Equal(t, "aaaaa", ack.WebHookURL)

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

				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), claimID).Times(2).Return(clData, nil)

				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).Times(2).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						b, _ := json.Marshal(map[string]interface{}{})
						return b, nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"PermanentResidentCard"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				assert.Len(t, resp.Credentials, 2)
				vc1 := resp.Credentials[0]

				assert.NotEmpty(t, vc1.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "VerifiedEmployee"}, vc1.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc1.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc1.OidcFormat)
				assert.NotEmpty(t, vc1.CredentialTemplate)
				assert.Equal(t, "ackID", *vc1.NotificationID)

				vc2 := resp.Credentials[1]
				assert.NotEmpty(t, vc2.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "PermanentResidentCard"}, vc2.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc2.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc2.OidcFormat)
				assert.NotEmpty(t, vc2.CredentialTemplate)
				assert.Equal(t, "ackID", *vc2.NotificationID)
			},
		},
		{
			name: "Success pre-authorized flow - multiple credentials same type with compose",
			setup: func(m *mocks) {
				claimID := uuid.NewString()
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IsPreAuthFlow: true,
						OrgID:         "asdasd",
						WebHookURL:    "aaaaa",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          claimID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								ClaimDataType:        oidc4ci.ClaimDataTypeVC,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialComposeConfiguration: &oidc4ci.CredentialComposeConfiguration{
									IDTemplate:     "some-template",
									OverrideIssuer: true,
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          claimID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								ClaimDataType:        oidc4ci.ClaimDataTypeVC,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialComposeConfiguration: &oidc4ci.CredentialComposeConfiguration{
									IDTemplate:     "some-template",
									OverrideIssuer: true,
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).Times(2).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						assert.Equal(t, "asdasd", ack.OrgID)
						assert.Equal(t, "aaaaa", ack.WebHookURL)

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

				m.composer.EXPECT().Compose(gomock.Any(), gomock.Any(), gomock.Any()).
					Times(2).DoAndReturn(func(
					ctx context.Context,
					credential *verifiable.Credential,
					req *oidc4ci.PrepareCredentialsRequest,
				) (*verifiable.Credential, error) {
					assert.EqualValues(t, "some-template",
						req.CredentialConfiguration.CredentialComposeConfiguration.IDTemplate)

					assert.True(t, req.CredentialConfiguration.CredentialComposeConfiguration.OverrideIssuer)
					return credential, nil
				})

				cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
					Subject: []verifiable.Subject{
						{
							ID: uuid.NewString(),
						},
					},
					Issuer: &verifiable.Issuer{
						ID: uuid.NewString(),
					},
					Context: []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential",
					},
				}, verifiable.CustomFields{})
				assert.NoError(t, err)

				clData := &oidc4ci.ClaimData{
					EncryptedData: &dataprotect.EncryptedData{
						Encrypted:      []byte{0x1, 0x2, 0x3},
						EncryptedNonce: []byte{0x0, 0x2},
					},
				}

				m.claimDataStore.EXPECT().GetAndDelete(gomock.Any(), claimID).Times(2).Return(clData, nil)

				m.crypto.EXPECT().Decrypt(gomock.Any(), clData.EncryptedData).Times(2).
					DoAndReturn(func(ctx context.Context, chunks *dataprotect.EncryptedData) ([]byte, error) {
						data, dataErr := cred.MarshalAsJSONLD()
						assert.NoError(t, dataErr)

						return data, nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				assert.Len(t, resp.Credentials, 2)
				vc1 := resp.Credentials[0]

				assert.NotEmpty(t, vc1.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, vc1.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc1.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc1.OidcFormat)
				assert.NotEmpty(t, vc1.CredentialTemplate)
				assert.Equal(t, "ackID", *vc1.NotificationID)

				vc2 := resp.Credentials[1]
				assert.NotEmpty(t, vc2.Credential)
				assert.Equal(t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, vc2.Credential.Contents().Types)
				assert.Equal(t, vcsverifiable.Format("jwt"), vc2.Format)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json-ld"), vc2.OidcFormat)
				assert.NotEmpty(t, vc2.CredentialTemplate)
				assert.Equal(t, "ackID", *vc2.NotificationID)
			},
		},
		{
			name: "Can not create ack",
			setup: func(m *mocks) {
				claimID := uuid.NewString()
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken:   "issuer-access-token",
						IsPreAuthFlow: true,
						OrgID:         "asdasd",
						WebHookURL:    "aaaaa",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          claimID,
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Nil(t, resp.Credentials[0].NotificationID)
			},
		},
		{
			name: "Failed to get claims for pre-authorized flow",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken:   "issuer-access-token",
						IsPreAuthFlow: true,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "get claims data")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Failed to send event for pre-authorized flow",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken:   "issuer-access-token",
						IsPreAuthFlow: true,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "publish error")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Failed to update tx state",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken:   "issuer-access-token",
						IsPreAuthFlow: true,
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								ClaimDataID:          uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
					},
				}, nil)

				m.ackService.EXPECT().CreateAck(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, ack *oidc4ci.Ack) (*string, error) {
						return lo.ToPtr("ackID"), nil
					})

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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "store err")
				assert.Nil(t, resp)
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
				assert.ErrorContains(t, err, "get tx")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Fail to make request to claim endpoint",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "http error")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Claim endpoint returned other than 200 OK status code",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "claim endpoint returned status code")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Fail to read response body from claim endpoint when status is not 200 OK",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},

								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "claim endpoint returned status code")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Fail to decode claim data",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "/oidc/idp//",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "decode claim data")
				assert.Nil(t, resp)
			},
		},
		{
			name: "Invalid audience claim",
			setup: func(m *mocks) {
				m.transactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialConfiguration: []*oidc4ci.TxCredentialConfiguration{
							{
								ID:                   uuid.NewString(),
								OIDCCredentialFormat: vcsverifiable.JwtVCJsonLD,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID:   "VerifiedEmployee",
									Type: "VerifiedEmployee",
								},
								CredentialConfigurationID: "VerifiedEmployeeIdentifier",
							},
						},
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
					TxID: "txID",
					CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
						{
							AudienceClaim:    "invalid",
							CredentialFormat: vcsverifiable.JwtVCJsonLD,
							CredentialTypes:  []string{"VerifiedEmployee"},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.ErrorContains(t, err, "invalid aud")
				assert.Nil(t, resp)
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
				composer:         NewMockcomposer(gomock.NewController(t)),
			}

			tt.setup(m)

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore:  m.transactionStore,
				ClaimDataStore:    m.claimDataStore,
				HTTPClient:        httpClient,
				EventService:      m.eventService,
				EventTopic:        spi.IssuerEventTopic,
				DataProtector:     m.crypto,
				AckService:        m.ackService,
				PrepareCredential: issuecredential.NewPrepareCredentialService(m.composer),
			})
			assert.NoError(t, err)

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

	t.Run("cwt", func(t *testing.T) {
		assert.Equal(t, vcsverifiable.CwtVcLD, srv.SelectProperOIDCFormat(vcsverifiable.Cwt,
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
	eventType spi.EventType, //nolint:unparam
) eventPublishFunc {
	t.Helper()

	return func(ctx context.Context, topic string, messages ...*spi.Event) error {
		assert.Len(t, messages, 1)
		assert.Equal(t, eventType, messages[0].Type)

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
		assert.Len(t, messages, 1)
		assert.Equal(t, spi.IssuerOIDCInteractionFailed, messages[0].Type)

		var ep oidc4ci.EventPayload

		jsonData, err := json.Marshal(messages[0].Data.(map[string]interface{}))
		assert.NoError(t, err)

		assert.NoError(t, json.Unmarshal(jsonData, &ep))

		assert.Equalf(t, string(errCode), ep.ErrorCode, "unexpected error code")
		assert.Equalf(t, errComponent, ep.ErrorComponent, "unexpected error component")

		if errMessage != "" {
			assert.Containsf(t, ep.Error, errMessage, "unexpected error message")
		}

		return nil
	}
}
