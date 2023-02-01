/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/trustbloc/vcs/pkg/event/spi"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	issuerWellKnownURL  = "https://issuer.example.com/.well-known/openid-configuration"
	walletWellKnownURL  = "https://wallet.example.com/.well-known/openid-configuration"
	issuerVCSPublicHost = "https://vcs.pb.example.com/"
)

//go:embed testdata/issuer_profile.json
var profileJSON []byte

func TestService_InitiateIssuance(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockWellKnownService = NewMockWellKnownService(gomock.NewController(t))
		eventService         = NewMockEventService(gomock.NewController(t))
		pinGenerator         = NewMockPinGenerator(gomock.NewController(t))
		issuanceReq          *oidc4ci.InitiateIssuanceRequest
		profile              *profileapi.Issuer
	)

	var testProfile profileapi.Issuer
	require.NoError(t, json.Unmarshal(profileJSON, &testProfile))

	testProfile.SigningDID = &profileapi.SigningDID{DID: "did:123"}

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						assert.Equal(t, oidc4ci.TransactionStateIssuanceInitiated, data.State)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
							},
						}, nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Success Pre-Auth with PIN",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				profile = &testProfile
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.True(t, len(data.UserPin) == 0)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.Equal(t, claimData, data.ClaimData)
						assert.Equal(t, oidc4ci.TransactionStateIssuanceInitiated, data.State)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID: profile.ID,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								UserPin:       "567",
							},
						}, nil
					})

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				pinGenerator.EXPECT().Generate("txID").Return("123456789")
				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, "123456789", tx.UserPin)
						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              initialOpState,
					UserPinRequired:      true,
					ClaimData:            claimData,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.Equal(t, "123456789", resp.UserPin)
				require.Equal(t, "openid-initiate-issuance://?credential_type=PermanentResidentCard&issuer=https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer&pre-authorized_code=super-secret-pre-auth-code&user_pin_required=true", //nolint
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Pre-Auth without PIN",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				profile = &testProfile
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.Equal(t, claimData, data.ClaimData)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID: profile.ID,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              initialOpState,
					UserPinRequired:      false,
					ClaimData:            claimData,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Equal(t, "openid-initiate-issuance://?credential_type=PermanentResidentCard&issuer=https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer&pre-authorized_code=super-secret-pre-auth-code&user_pin_required=false", //nolint
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Pre-Auth without PIN and without template",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				cp := testProfile
				cp.CredentialTemplates = []*profileapi.CredentialTemplate{cp.CredentialTemplates[0]}
				profile = &cp
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID: profile.ID,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					ClaimEndpoint:      "https://vcs.pb.example.com/claim",
					OpState:            initialOpState,
					UserPinRequired:    false,
					ClaimData:          claimData,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Equal(t, "openid-initiate-issuance://?credential_type=PermanentResidentCard&issuer=https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer&pre-authorized_code=super-secret-pre-auth-code&user_pin_required=false", //nolint
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Fail Pre-Auth with PIN because of saving pin tx",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				profile = &testProfile
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.True(t, len(data.UserPin) == 0)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.Equal(t, claimData, data.ClaimData)
						assert.Equal(t, oidc4ci.TransactionStateIssuanceInitiated, data.State)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID: profile.ID,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								UserPin:       "567",
							},
						}, nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				pinGenerator.EXPECT().Generate("txID").Return("123456789")
				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("pin saving error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              initialOpState,
					UserPinRequired:      true,
					ClaimData:            claimData,
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "store pin tx: pin saving error")
			},
		},
		{
			name: "Error because of event publishing",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.Equal(t, claimData, data.ClaimData)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return errors.New("unexpected error")
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              initialOpState,
					UserPinRequired:      false,
					ClaimData:            claimData,
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "unexpected error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Profile is not active",
			setup: func() {
				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     false,
					OIDCConfig: &profileapi.OIDC4CIConfig{},
					VCConfig:   &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrProfileNotActive)
			},
		},
		{
			name: "OIDC4CI authorized code flow not supported",
			setup: func() {
				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
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
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrAuthorizedCodeFlowNotSupported)
			},
		},
		{
			name: "VC options not configured",
			setup: func() {
				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDC4CIConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrVCOptionsNotConfigured)
			},
		},
		{
			name: "Credential template not configured",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDC4CIConfig{},
					VCConfig:   &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotConfigured)
			},
		},
		{
			name: "Credential template ID is not required",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorContains(t, err, "credential template should be specified")
			},
		},
		{
			name: "Credential template not found",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID3",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotFound)
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client well-known parameter",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        walletWellKnownURL,
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to do well-known request",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&oidc4ci.Transaction{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					nil, errors.New("invalid json"))

				eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   walletWellKnownURL,
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Fail to get OIDC configuration",
			setup: func() {
				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					nil, errors.New("well known service error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
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
					&oidc4ci.OIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "store error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore:    mockTransactionStore,
				WellKnownService:    mockWellKnownService,
				IssuerVCSPublicHost: issuerVCSPublicHost,
				EventService:        eventService,
				EventTopic:          spi.IssuerEventTopic,
				PinGenerator:        pinGenerator,
			})
			require.NoError(t, err)

			resp, err := svc.InitiateIssuance(context.Background(), issuanceReq, profile)
			tt.check(t, resp, err)
		})
	}
}
