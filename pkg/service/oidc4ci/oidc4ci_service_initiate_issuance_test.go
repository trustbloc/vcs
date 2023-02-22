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
	"time"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
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
		mockClaimDataStore   = NewMockClaimDataStore(gomock.NewController(t))
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
								CredentialFormat: verifiable.Jwt,
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

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
						assert.NotEmpty(t, data.ClaimDataID)
						assert.Equal(t, oidc4ci.TransactionStateIssuanceInitiated, data.State)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID:        profile.ID,
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								UserPin:       "567",
							},
						}, nil
					})

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Equal(t,
					"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22PermanentResidentCard%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D", //nolint
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
						assert.NotEmpty(t, data.ClaimDataID)

						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID:        profile.ID,
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22PermanentResidentCard%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%2C%22user_pin_required%22%3Afalse%7D%7D%7D", //nolint
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
								ProfileID:        profile.ID,
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22PermanentResidentCard%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%2C%22user_pin_required%22%3Afalse%7D%7D%7D", //nolint
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Pre-Auth without PIN and without template and empty state",
			setup: func() {
				initialOpState := ""
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				cp := testProfile
				cp.CredentialTemplates = []*profileapi.CredentialTemplate{cp.CredentialTemplates[0]}
				profile = &cp

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						data *oidc4ci.TransactionData,
						params ...func(insertOptions *oidc4ci.InsertOptions),
					) (*oidc4ci.Transaction, error) {
						return &oidc4ci.Transaction{
							ID: "txID",
							TransactionData: oidc4ci.TransactionData{
								ProfileID:        profile.ID,
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Fissuer%2Ftest_issuer%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22PermanentResidentCard%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%2C%22user_pin_required%22%3Afalse%7D%7D%7D", //nolint
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Fail Pre-Auth with with invalid format",
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
								ProfileID:        profile.ID,
								CredentialFormat: verifiable.Format("anything"),
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
							},
						}, nil
					})

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)
				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
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
				require.ErrorContains(t, err, "unsupported vc mapping for format: anything")
				require.Nil(t, resp)
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
						assert.NotEmpty(t, data.ClaimDataID)
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

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

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
			name: "Fail Pre-Auth with PIN because of error during saving claim data",
			setup: func() {
				initialOpState := "eyJhbGciOiJSU0Et"
				claimData := map[string]interface{}{
					"my_awesome_claim": "claim",
				}

				profile = &testProfile
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("", errors.New("create error"))

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)

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
				require.ErrorContains(t, err, "store claim data")
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
						assert.NotEmpty(t, data.ClaimDataID)

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

				mockClaimDataStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return("claimDataID", nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&oidc4ci.Transaction{
						TransactionData: oidc4ci.TransactionData{
							CredentialFormat: verifiable.Jwt,
						},
					}, nil)

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

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
					&oidc4ci.Transaction{
						TransactionData: oidc4ci.TransactionData{
							CredentialFormat: verifiable.Jwt,
						},
					}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					nil, errors.New("invalid json"))

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Contains(t, resp.InitiateIssuanceURL, "openid-credential-offer://")
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
				ClaimDataStore:      mockClaimDataStore,
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

func TestCalculateExpiration(t *testing.T) {
	t.Run("in request", func(t *testing.T) {
		svc, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		expected := time.Now().UTC().Add(25 * time.Minute)

		got := svc.GetCredentialsExpirationTime(&oidc4ci.InitiateIssuanceRequest{
			CredentialExpiresAt: &expected,
		}, nil)

		assert.Equal(t, expected, got)
	})

	t.Run("in template", func(t *testing.T) {
		svc, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		expected := time.Now().UTC().Add(60 * time.Hour)

		got := svc.GetCredentialsExpirationTime(&oidc4ci.InitiateIssuanceRequest{
			CredentialExpiresAt: nil,
		}, &profileapi.CredentialTemplate{
			CredentialDefaultExpirationDuration: lo.ToPtr(60 * time.Hour),
		})

		assert.Equal(t, got.Truncate(time.Hour*24), expected.Truncate(time.Hour*24))
	})

	t.Run("default", func(t *testing.T) {
		svc, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		expected := time.Now().UTC().Add(365 * 24 * time.Hour)

		got := svc.GetCredentialsExpirationTime(&oidc4ci.InitiateIssuanceRequest{
			CredentialExpiresAt: nil,
		}, &profileapi.CredentialTemplate{
			CredentialDefaultExpirationDuration: nil,
		})

		assert.Equal(t, got.Truncate(time.Hour*24), expected.Truncate(time.Hour*24))
	})
}

func TestService_InitiateIssuanceWithRemoteStore(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockWellKnownService = NewMockWellKnownService(gomock.NewController(t))
		eventService         = NewMockEventService(gomock.NewController(t))
		pinGenerator         = NewMockPinGenerator(gomock.NewController(t))
		referenceStore       = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
		issuanceReq          *oidc4ci.InitiateIssuanceRequest
		profile              *profileapi.Issuer
	)

	var testProfile profileapi.Issuer
	require.NoError(t, json.Unmarshal(profileJSON, &testProfile))

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success with reference store",
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
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
							},
						}, nil
					})
				referenceStore = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
				referenceStore.EXPECT().Create(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						request *oidc4ci.CredentialOfferResponse,
					) (string, error) {
						return "https://remote_url/file.jwt", nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.Contains(t, resp.InitiateIssuanceURL,
					"https://wallet.example.com/initiate_issuance?"+
						"credential_offer_uri=https%3A%2F%2Fremote_url%2Ffile.jwt")
			},
		},
		{
			name: "Fail uploading to remote",
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
								CredentialFormat: verifiable.Jwt,
								CredentialTemplate: &profileapi.CredentialTemplate{
									ID: "templateID",
								},
							},
						}, nil
					})
				referenceStore = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
				referenceStore.EXPECT().Create(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						request *oidc4ci.CredentialOfferResponse,
					) (string, error) {
						return "", errors.New("fail uploading to remote")
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.OIDCConfiguration{}, nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
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
				require.ErrorContains(t, err, "fail uploading to remote")
				require.Nil(t, resp)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore:              mockTransactionStore,
				WellKnownService:              mockWellKnownService,
				IssuerVCSPublicHost:           issuerVCSPublicHost,
				EventService:                  eventService,
				PinGenerator:                  pinGenerator,
				CredentialOfferReferenceStore: referenceStore,
				EventTopic:                    spi.IssuerEventTopic,
			})
			require.NoError(t, err)

			resp, err := svc.InitiateIssuance(context.Background(), issuanceReq, profile)
			tt.check(t, resp, err)
		})
	}
}
