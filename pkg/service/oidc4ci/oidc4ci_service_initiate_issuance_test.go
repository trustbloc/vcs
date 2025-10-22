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
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	issuerWellKnownURL  = "https://issuer.example.com/.well-known/openid-configuration"
	walletWellKnownURL  = "https://wallet.example.com/.well-known/openid-configuration"
	issuerVCSPublicHost = "https://vcs.pb.example.com"
)

//go:embed testdata/issuer_profile.json
var profileJSON []byte

//go:embed testdata/issuer_profile_without_template.json
var profileWithoutTemplateJSON []byte

type mocks struct {
	transactionStore    *MockTransactionStore
	wellKnownService    *MockWellKnownService
	claimDataStore      *MockClaimDataStore
	eventService        *MockEventService
	pinGenerator        *MockPinGenerator
	crypto              *MockDataProtector
	jsonSchemaValidator *MockJSONSchemaValidator
	ackService          *MockAckService
	documentLoader      *jsonld.DefaultDocumentLoader
	composer            *Mockcomposer
	wellKnown           *MockwellKnownProvider
}

func TestService_InitiateIssuance(t *testing.T) {
	var (
		issuanceReq  *oidc4ci.InitiateIssuanceRequest
		profile      *profileapi.Issuer
		degreeClaims = map[string]interface{}{
			"name":   "John Doe",
			"spouse": "Jane Doe",
			"degree": map[string]interface{}{
				"type":   "BachelorDegree",
				"degree": "MIT",
			},
		}
	)

	var testProfile profileapi.Issuer
	require.NoError(t, json.Unmarshal(profileJSON, &testProfile))

	testProfile.SigningDID = &profileapi.SigningDID{DID: "did:123"}

	tests := []struct {
		name  string
		setup func(mocks *mocks)
		check func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success auth flow",
			setup: func(mocks *mocks) {
				now := lo.ToPtr(time.Now().UTC())

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)
						assert.Equal(t, "test_issuer", data.ProfileID)
						assert.Equal(t, "1.1", data.ProfileVersion)
						assert.Equal(t, false, data.IsPreAuthFlow)
						assert.Empty(t, data.PreAuthCode)
						assert.Equal(t, "test_org", data.OrgID)
						assert.Equal(t, "https://example.com/auth", data.AuthorizationEndpoint)
						assert.Equal(t, "https://example.com/pushed_authorization_request_endpoint",
							data.PushedAuthorizationRequestEndpoint)
						assert.Equal(t, "https://example.com/token_endpoint", data.TokenEndpoint)
						assert.Equal(t, "eyJhbGciOiJSU0Et", data.OpState)
						assert.Equal(t, "https://vcs.pb.example.com/oidc/redirect", data.RedirectURI)
						assert.Equal(t, "authorization_code", data.GrantType)
						assert.Equal(t, "token", data.ResponseType)
						assert.Equal(t, []string{"openid", "profile"}, data.Scope)
						assert.Empty(t, data.IssuerAuthCode)
						assert.Empty(t, data.IssuerToken)
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)
						assert.Empty(t, data.WebHookURL)
						assert.Equal(t, "123456789", data.UserPin)
						assert.Equal(t, "did:123", data.DID)
						assert.False(t, data.WalletInitiatedIssuance)

						assert.Len(t, data.CredentialConfiguration, 2)

						prcCredConf := data.CredentialConfiguration[0]
						assert.NotEmpty(t, prcCredConf.CredentialTemplate)
						assert.Equal(t, verifiable.OIDCFormat("jwt_vc_json"), prcCredConf.OIDCCredentialFormat)
						assert.Equal(t, "https://vcs.pb.example.com/claim1", prcCredConf.ClaimEndpoint)
						assert.Empty(t, prcCredConf.ClaimDataID)
						assert.Equal(t, "vc_name1", prcCredConf.CredentialName)
						assert.Equal(t, "vc_desc1", prcCredConf.CredentialDescription)
						assert.Equal(t, "PermanentResidentCardIdentifier", prcCredConf.CredentialConfigurationID)
						assert.NotEmpty(t, prcCredConf.CredentialExpiresAt)
						assert.Empty(t, prcCredConf.PreAuthCodeExpiresAt)
						assert.Empty(t, prcCredConf.AuthorizationDetails)

						univDegreeCredConf := data.CredentialConfiguration[1]
						assert.NotEmpty(t, univDegreeCredConf.CredentialTemplate)
						assert.Equal(t, verifiable.OIDCFormat("jwt_vc_json"), univDegreeCredConf.OIDCCredentialFormat)
						assert.Equal(t, "https://vcs.pb.example.com/claim2", univDegreeCredConf.ClaimEndpoint)
						assert.Empty(t, univDegreeCredConf.ClaimDataID)
						assert.Equal(t, "vc_name2", univDegreeCredConf.CredentialName)
						assert.Equal(t, "vc_desc2", univDegreeCredConf.CredentialDescription)
						assert.Equal(t, "UniversityDegreeCredentialIdentifier", univDegreeCredConf.CredentialConfigurationID)
						assert.NotEmpty(t, univDegreeCredConf.CredentialExpiresAt)
						assert.Empty(t, prcCredConf.PreAuthCodeExpiresAt)
						assert.Empty(t, prcCredConf.AuthorizationDetails)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID2",
										},
										CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
									},
								},
							},
						}, nil
					})

				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Return("123456789")

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint:           "https://wallet.example.com/initiate_issuance",
						AuthorizationEndpoint:              "https://example.com/auth",
						PushedAuthorizationRequestEndpoint: "https://example.com/pushed_authorization_request_endpoint",
						TokenEndpoint:                      "https://example.com/token_endpoint",
					}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						payload, ok := messages[0].Data.(map[string]interface{})
						assert.True(t, ok)

						assert.NotEmpty(t, payload["credentialTemplateID"])
						assert.Equal(t, payload["format"], "jwt_vc_json-ld")

						credentialsData, ok := payload["credentials"].(map[string]interface{})
						assert.True(t, ok)

						assert.Len(t, credentialsData, 2)

						format, ok := credentialsData["templateID"]
						assert.True(t, ok)
						assert.Equal(t, format, "jwt_vc_json-ld")

						format, ok = credentialsData["templateID2"]
						assert.True(t, ok)
						assert.Equal(t, format, "jwt_vc_json-ld")

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "",
					ClientWellKnownURL:        walletWellKnownURL,
					GrantType:                 "authorization_code",
					ResponseType:              "token",
					Scope:                     []string{"openid", "profile"},
					OpState:                   "eyJhbGciOiJSU0Et",
					UserPinRequired:           true,
					WalletInitiatedIssuance:   false,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData: map[string]interface{}{
								"key1": "value1",
							},
							ClaimEndpoint:         "https://vcs.pb.example.com/claim1",
							CredentialTemplateID:  "templateID",
							CredentialExpiresAt:   now,
							CredentialName:        "vc_name1",
							CredentialDescription: "vc_desc1",
						},
						{
							ClaimData: map[string]interface{}{
								"key2": "value2",
							},
							ClaimEndpoint:         "https://vcs.pb.example.com/claim2",
							CredentialTemplateID:  "templateID2",
							CredentialExpiresAt:   now,
							CredentialName:        "vc_name2",
							CredentialDescription: "vc_desc2",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				require.Equal(t, "https://wallet.example.com/initiate_issuance?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%2C%22UniversityDegreeCredentialIdentifier%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et%22%7D%7D%7D", resp.InitiateIssuanceURL)
				require.Equal(t, oidc4ci.ContentTypeApplicationJSON, resp.ContentType)
			},
		},
		{
			name: "Success pre auth flow",
			setup: func(mocks *mocks) {
				now := lo.ToPtr(time.Now().UTC())

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)
						assert.Equal(t, "test_issuer", data.ProfileID)
						assert.Equal(t, "1.1", data.ProfileVersion)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.NotEmpty(t, data.PreAuthCode)
						assert.Equal(t, "test_org", data.OrgID)
						assert.Equal(t, "https://example.com/auth", data.AuthorizationEndpoint)
						assert.Equal(t, "https://example.com/pushed_authorization_request_endpoint",
							data.PushedAuthorizationRequestEndpoint)
						assert.Equal(t, "https://example.com/token_endpoint", data.TokenEndpoint)
						assert.NotEmpty(t, data.OpState)
						assert.Equal(t, "https://vcs.pb.example.com/oidc/redirect", data.RedirectURI)
						assert.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", data.GrantType)
						assert.Equal(t, "token", data.ResponseType)
						assert.Equal(t, []string{"openid", "profile"}, data.Scope)
						assert.Empty(t, data.IssuerAuthCode)
						assert.Empty(t, data.IssuerToken)
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)
						assert.Empty(t, data.WebHookURL)
						assert.Equal(t, "123456789", data.UserPin)
						assert.Equal(t, "did:123", data.DID)
						assert.False(t, data.WalletInitiatedIssuance)

						assert.Len(t, data.CredentialConfiguration, 3)

						prcCredConf := data.CredentialConfiguration[0]
						assert.NotEmpty(t, prcCredConf.CredentialTemplate)
						assert.Equal(t, verifiable.OIDCFormat("jwt_vc_json"), prcCredConf.OIDCCredentialFormat)
						assert.Empty(t, prcCredConf.ClaimEndpoint)
						assert.NotEmpty(t, prcCredConf.ClaimDataID)
						assert.Equal(t, "vc_name1", prcCredConf.CredentialName)
						assert.Equal(t, "vc_desc1", prcCredConf.CredentialDescription)
						assert.Equal(t, "PermanentResidentCardIdentifier", prcCredConf.CredentialConfigurationID)
						assert.NotEmpty(t, prcCredConf.CredentialExpiresAt)
						assert.NotEmpty(t, prcCredConf.PreAuthCodeExpiresAt)
						assert.Empty(t, prcCredConf.AuthorizationDetails)

						univDegreeCredConf := data.CredentialConfiguration[1]
						assert.NotEmpty(t, univDegreeCredConf.CredentialTemplate)
						assert.Equal(t, verifiable.OIDCFormat("jwt_vc_json"), univDegreeCredConf.OIDCCredentialFormat)
						assert.Empty(t, univDegreeCredConf.ClaimEndpoint)
						assert.NotEmpty(t, univDegreeCredConf.ClaimDataID)
						assert.Equal(t, "vc_name2", univDegreeCredConf.CredentialName)
						assert.Equal(t, "vc_desc2", univDegreeCredConf.CredentialDescription)
						assert.Equal(t, "UniversityDegreeCredentialIdentifier", univDegreeCredConf.CredentialConfigurationID)
						assert.NotEmpty(t, univDegreeCredConf.CredentialExpiresAt)
						assert.NotEmpty(t, prcCredConf.PreAuthCodeExpiresAt)
						assert.Empty(t, prcCredConf.AuthorizationDetails)

						univDegreeCredConf = data.CredentialConfiguration[2]
						assert.NotEmpty(t, univDegreeCredConf.CredentialTemplate)
						assert.Equal(t, verifiable.OIDCFormat("jwt_vc_json"), univDegreeCredConf.OIDCCredentialFormat)
						assert.Empty(t, univDegreeCredConf.ClaimEndpoint)
						assert.NotEmpty(t, univDegreeCredConf.ClaimDataID)
						assert.Equal(t, "vc_name2", univDegreeCredConf.CredentialName)
						assert.Equal(t, "vc_desc2", univDegreeCredConf.CredentialDescription)
						assert.Equal(t, "UniversityDegreeCredentialIdentifier", univDegreeCredConf.CredentialConfigurationID)
						assert.NotEmpty(t, univDegreeCredConf.CredentialExpiresAt)
						assert.NotEmpty(t, prcCredConf.PreAuthCodeExpiresAt)
						assert.Empty(t, prcCredConf.AuthorizationDetails)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID2",
										},
										CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
									},
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID2",
										},
										CredentialConfigurationID: "UniversityDegreeCredentialIdentifier",
									},
								},
							},
						}, nil
					})

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return(nil)
				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Return("123456789")

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Times(3).
					Return(chunks, nil)

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(3).DoAndReturn(
					func(ctx context.Context, profileTTL int32, data *issuecredential.ClaimData) (string, error) {
						assert.Equal(t, chunks, data.EncryptedData)

						return "claimDataID", nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint:           "https://wallet.example.com/initiate_issuance",
						AuthorizationEndpoint:              "https://example.com/auth",
						PushedAuthorizationRequestEndpoint: "https://example.com/pushed_authorization_request_endpoint",
						TokenEndpoint:                      "https://example.com/token_endpoint",
					}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						payload, ok := messages[0].Data.(map[string]interface{})
						assert.True(t, ok)

						assert.NotEmpty(t, payload["credentialTemplateID"])
						assert.Equal(t, payload["format"], "jwt_vc_json-ld")

						credentialsData, ok := payload["credentials"].(map[string]interface{})
						assert.True(t, ok)

						assert.Len(t, credentialsData, 2)

						format, ok := credentialsData["templateID"]
						assert.True(t, ok)
						assert.Equal(t, format, "jwt_vc_json-ld")

						format, ok = credentialsData["templateID2"]
						assert.True(t, ok)
						assert.Equal(t, format, "jwt_vc_json-ld")

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "",
					ClientWellKnownURL:        walletWellKnownURL,
					GrantType:                 "", // Pass empty value to cover default for GrantType.
					ResponseType:              "token",
					Scope:                     []string{"openid", "profile"},
					OpState:                   "eyJhbGciOiJSU0Et",
					UserPinRequired:           true,
					WalletInitiatedIssuance:   false,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData: map[string]interface{}{
								"key1": "value1",
							},
							ClaimEndpoint:         "",
							CredentialTemplateID:  "templateID",
							CredentialExpiresAt:   now,
							CredentialName:        "vc_name1",
							CredentialDescription: "vc_desc1",
						},
						{
							ClaimData: map[string]interface{}{
								"key2": "value2",
							},
							ClaimEndpoint:         "",
							CredentialTemplateID:  "templateID2",
							CredentialExpiresAt:   now,
							CredentialName:        "vc_name2",
							CredentialDescription: "vc_desc2",
						},
						{
							ClaimData: map[string]interface{}{
								"key3": "value3",
							},
							ClaimEndpoint:         "",
							CredentialTemplateID:  "templateID2",
							CredentialExpiresAt:   now,
							CredentialName:        "vc_name2",
							CredentialDescription: "vc_desc2",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				require.Equal(t, "https://wallet.example.com/initiate_issuance?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%2C%22UniversityDegreeCredentialIdentifier%22%2C%22UniversityDegreeCredentialIdentifier%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et%22%7D%7D%7D", resp.InitiateIssuanceURL)
				require.Equal(t, oidc4ci.ContentTypeApplicationJSON, resp.ContentType)
			},
		},
		{
			name: "Success wallet flow",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								State: data.State,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCard",
									},
								},
							},
						}, nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL:      walletWellKnownURL,
					OpState:                 "eyJhbGciOiJSU0Et",
					GrantType:               "authorization_code",
					Scope:                   []string{"openid", "profile"},
					WalletInitiatedIssuance: true,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				assert.Equal(t, issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization, resp.Tx.State)
				require.Equal(t, "https://wallet.example.com/initiate_issuance?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCard%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et%22%7D%7D%7D", resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Pre-Auth with PIN",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"name":   "John Doe",
					"spouse": "Jane Doe",
					"degree": map[string]interface{}{
						"type":   "BachelorDegree",
						"degree": "MIT",
					},
				}

				profile = &testProfile
				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.True(t, len(data.UserPin) > 0)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.NotEmpty(t, data.CredentialConfiguration[0].ClaimDataID)
						assert.Equal(t, "PermanentResidentCardIdentifier", data.CredentialConfiguration[0].CredentialConfigurationID)
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								ProfileID:     profile.ID,
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								UserPin:       "123456789",
								GrantType:     "authorization_code",
								Scope:         []string{"openid", "profile"},
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).DoAndReturn(
					func(ctx context.Context, profileTTL int32, data *issuecredential.ClaimData) (string, error) {
						assert.Equal(t, chunks, data.EncryptedData)

						return "claimDataID", nil
					})

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Return("123456789")

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            claimData,
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.Equal(t, "123456789", resp.UserPin)
				assert.NotNil(t, resp.Tx)
				require.Equal(t,
					"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%2Ftest_issuer%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A6%2C%22description%22%3A%22Pin%22%7D%7D%7D%7D",
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Pre-Auth without PIN",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := degreeClaims

				profile = &testProfile
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.NotEmpty(t, data.CredentialConfiguration[0].ClaimDataID)
						assert.Equal(t, "PermanentResidentCardIdentifier", data.CredentialConfiguration[0].CredentialConfigurationID)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								ProfileID:     profile.ID,
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("claimDataID", nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					Scope:              []string{"openid", "profile"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            claimData,
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%2Ftest_issuer%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%7D%7D%7D",
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Compose feature",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"name":   "John Doe",
					"spouse": "Jane Doe",
					"degree": map[string]interface{}{
						"type":   "BachelorDegree",
						"degree": "MIT",
					},
				}

				profile = &testProfile
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)

						configuration := data.CredentialConfiguration[0]

						assert.NotEmpty(t, configuration.ClaimDataID)
						assert.EqualValues(t, issuecredential.ClaimDataTypeVC, configuration.ClaimDataType)

						assert.EqualValues(t, "some-template",
							configuration.CredentialComposeConfiguration.IDTemplate)

						assert.True(t, configuration.CredentialComposeConfiguration.OverrideIssuer)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								ProfileID:     profile.ID,
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("claimDataID", nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				targetCred := map[string]interface{}{
					"type": []string{
						"VerifiableCredential",
						"PermanentResidentCard",
					},
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					"credentialSubject": claimData,
				}

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "",
					ClientWellKnownURL:        walletWellKnownURL,
					GrantType:                 oidc4ci.GrantTypePreAuthorizedCode,
					ResponseType:              "",
					Scope:                     []string{"openid", "profile"},
					OpState:                   initialOpState,
					UserPinRequired:           false,
					WalletInitiatedIssuance:   false,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							CredentialTemplateID: "templateID",
							ComposeCredential: &oidc4ci.InitiateIssuanceComposeCredential{
								Credential:              &targetCred,
								IDTemplate:              "some-template",
								OverrideIssuer:          true,
								PerformStrictValidation: true,
							},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%2Ftest_issuer%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%7D%7D%7D",
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Success Compose feature with no template",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := map[string]interface{}{
					"name":   "John Doe",
					"spouse": "Jane Doe",
					"degree": map[string]interface{}{
						"type":   "BachelorDegree",
						"degree": "MIT",
					},
				}

				var tempProfile *profileapi.Issuer
				require.NoError(t, json.Unmarshal(profileWithoutTemplateJSON, &tempProfile)) // hack profile ref
				profile = tempProfile

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)

						configuration := data.CredentialConfiguration[0]

						assert.NotEmpty(t, configuration.ClaimDataID)
						assert.EqualValues(t, issuecredential.ClaimDataTypeVC, configuration.ClaimDataType)

						assert.EqualValues(t, "some-template",
							configuration.CredentialComposeConfiguration.IDTemplate)

						assert.True(t, configuration.CredentialComposeConfiguration.OverrideIssuer)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								ProfileID:     profile.ID,
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("claimDataID", nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				targetCred := map[string]interface{}{
					"type": []string{
						"VerifiableCredential",
						"PermanentResidentCard",
					},
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					"credentialSubject": claimData,
				}

				targetCredBytes, err := json.Marshal(targetCred)
				require.NoError(t, err)
				assert.NoError(t, json.Unmarshal(targetCredBytes, &targetCred)) // just to ensure type castings

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "",
					ClientWellKnownURL:        walletWellKnownURL,
					GrantType:                 oidc4ci.GrantTypePreAuthorizedCode,
					ResponseType:              "",
					Scope:                     []string{"openid", "profile"},
					OpState:                   initialOpState,
					UserPinRequired:           false,
					WalletInitiatedIssuance:   false,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ComposeCredential: &oidc4ci.InitiateIssuanceComposeCredential{
								Credential:     &targetCred,
								IDTemplate:     "some-template",
								OverrideIssuer: true,
							},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				assert.NotNil(t, resp.Tx)
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%2Ftest_issuer%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%7D%7D%7D",
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Fail Compose feature with strict validation",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				claimData := map[string]interface{}{
					"name":                               "John Doe",
					"spouse":                             "Jane Doe",
					"totally-random-field-not-in-jsonld": "should not be here",
					"degree": map[string]interface{}{
						"type":   "BachelorDegree",
						"degree": "MIT",
					},
				}

				var tempProfile *profileapi.Issuer
				require.NoError(t, json.Unmarshal(profileWithoutTemplateJSON, &tempProfile)) // hack profile ref
				profile = tempProfile

				targetCred := map[string]interface{}{
					"type": []string{
						"VerifiableCredential",
						"PermanentResidentCard",
					},
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					"issuer":            "did:orb:anything",
					"issuanceDate":      "2020-03-10T04:24:12.164Z",
					"credentialSubject": claimData,
				}

				targetCredBytes, err := json.Marshal(targetCred)
				require.NoError(t, err)
				assert.NoError(t, json.Unmarshal(targetCredBytes, &targetCred)) // just to ensure type castings

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "",
					ClientWellKnownURL:        walletWellKnownURL,
					GrantType:                 oidc4ci.GrantTypePreAuthorizedCode,
					ResponseType:              "",
					Scope:                     []string{"openid", "profile"},
					OpState:                   initialOpState,
					UserPinRequired:           false,
					WalletInitiatedIssuance:   false,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ComposeCredential: &oidc4ci.InitiateIssuanceComposeCredential{
								Credential:              &targetCred,
								IDTemplate:              "some-template",
								OverrideIssuer:          true,
								PerformStrictValidation: true,
							},
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Error(t, err, "JSON-LD doc has different structure after compaction")
			},
		},
		{
			name: "Success Pre-Auth without PIN and without template and empty state",
			setup: func(mocks *mocks) {
				initialOpState := ""
				expectedCode := "super-secret-pre-auth-code"
				claimData := degreeClaims

				cp := testProfile
				cp.CredentialTemplates = []*profileapi.CredentialTemplate{cp.CredentialTemplates[0]}
				profile = &cp

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("claimDataID", nil)

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								ProfileID:     profile.ID,
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)
				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					Scope:              []string{"openid", "profile"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData: claimData,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Equal(t, "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fvcs.pb.example.com%2Foidc%2Fidp%2Ftest_issuer%22%2C%22credential_configuration_ids%22%3A%5B%22PermanentResidentCardIdentifier%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22super-secret-pre-auth-code%22%7D%7D%7D",
					resp.InitiateIssuanceURL)
			},
		},
		{
			name: "Fail Pre-Auth with PIN because of error during saving claim data",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				claimData := degreeClaims

				profile = &testProfile
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)

				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("", errors.New("create error"))

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Times(0)

				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            claimData,
							CredentialTemplateID: "templateID",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "store claim data")
			},
		},
		{
			name: "Fail Pre-Auth via CredentialTemplateID: missed claim data",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				profile = &testProfile

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Times(0)
				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)
				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Times(0)
				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            nil,
							CredentialTemplateID: "templateID",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "claim_data param is not supplied")
			},
		},
		{
			name: "Fail Auth via CredentialTemplateID: missed claimEndpoint",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				profile = &testProfile

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Times(0)
				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)
				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Times(0)
				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "",
							CredentialTemplateID: "templateID",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "claim_endpoint param is not supplied")
			},
		},
		{
			name: "Fail Pre-Auth via CredentialConfiguration: missed claim data",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				profile = &testProfile

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Times(0)
				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)
				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Times(0)
				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData: nil,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "claim_data param is not supplied")
			},
		},
		{
			name: "Fail Auth via CredentialConfiguration: missed claimEndpoint",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				profile = &testProfile

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Times(0)
				mocks.pinGenerator.EXPECT().Generate(gomock.Any()).Times(0)
				mocks.transactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)
				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Times(0)
				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    true,
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint: "",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "claim_endpoint param is not supplied")
			},
		},
		{
			name: "Fail PreAuth via CredentialConfiguration: failed to encrypt claims",
			setup: func(mocks *mocks) {
				initialOpState := ""
				claimData := degreeClaims

				cp := testProfile
				cp.CredentialTemplates = []*profileapi.CredentialTemplate{cp.CredentialTemplates[0]}
				profile = &cp

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("unexpected encrypt error"))

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					Scope:              []string{"openid", "profile"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData: claimData,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "unexpected encrypt error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail PreAuth via CredentialConfiguration: unable to find credential configuration ID",
			setup: func(mocks *mocks) {
				initialOpState := ""
				claimData := degreeClaims

				profile = &testProfile

				delete(profile.CredentialMetaData.CredentialsConfigurationSupported, "UniversityDegreeCredentialIdentifier")

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					Scope:              []string{"openid", "profile"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							CredentialTemplateID: "templateID2",
							ClaimData:            claimData,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "credential configuration not found for requested template id")
				require.Nil(t, resp)
			},
		},
		{
			name: "Success with Dynamic WellKnown",
			setup: func(mocks *mocks) {
				initialOpState := ""
				claimData := degreeClaims

				b, err := json.Marshal(testProfile)
				assert.NoError(t, err)

				assert.NoError(t, json.Unmarshal(b, &profile))
				delete(profile.CredentialMetaData.CredentialsConfigurationSupported, "UniversityDegreeCredentialIdentifier")
				profile.OIDCConfig.DynamicWellKnownSupported = true

				mocks.wellKnown.EXPECT().
					AddDynamicConfiguration(gomock.Any(), profile.ID, gomock.Any(), gomock.Any()).
					Return(nil)

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("schema validation err"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					Scope:              []string{"openid", "profile"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							CredentialTemplateID: "templateID2",
							ClaimData:            claimData,
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "schema validation err")
				require.Nil(t, resp)
			},
		},
		{
			name: "Error because of event publishing",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				expectedCode := "super-secret-pre-auth-code"
				claimData := degreeClaims

				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.NotEqual(t, data.OpState, initialOpState)
						assert.Equal(t, data.OpState, data.PreAuthCode)
						assert.Empty(t, data.UserPin)
						assert.Equal(t, true, data.IsPreAuthFlow)
						assert.NotEmpty(t, data.CredentialConfiguration[0].ClaimDataID)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								PreAuthCode:   expectedCode,
								IsPreAuthFlow: true,
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
										CredentialConfigurationID: "PermanentResidentCardIdentifier",
									},
								},
							},
						}, nil
					})

				chunks := &dataprotect.EncryptedData{
					Encrypted:      []byte{0x1, 0x2, 0x3},
					EncryptedNonce: []byte{0x0, 0x2},
				}

				mocks.crypto.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
					Return(chunks, nil)
				mocks.claimDataStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return("claimDataID", nil)

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return errors.New("unexpected error")
					})

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil).AnyTimes()

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: issuerWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            claimData,
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "unexpected error")
				require.Nil(t, resp)
			},
		},
		{
			name: "VC options not configured",
			setup: func(mocks *mocks) {
				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",

					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrVCOptionsNotConfigured)
			},
		},
		{
			name: "Credential template not configured",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &profileapi.Issuer{
					Active:     true,
					OIDCConfig: &profileapi.OIDCConfig{},
					VCConfig:   &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotConfigured)
			},
		},
		{
			name: "Credential template ID should be specified if profile supports more than one template",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							CredentialTemplateID: "",
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
						},
					},
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
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID_unknown",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotFound)
			},
		},
		{
			name: "Credential configuration not found",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID3",
						},
					},
				}

				profile = &testProfile
				profile.OIDCConfig.DynamicWellKnownSupported = false
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorContains(t, err, "credential configuration not found for requested template id")
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client well-known parameter",
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					Return(&issuecredential.Transaction{
						TransactionData: issuecredential.TransactionData{
							CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
								{
									OIDCCredentialFormat: verifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        walletWellKnownURL,
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
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
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return(
					&issuecredential.Transaction{
						TransactionData: issuecredential.TransactionData{
							CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
								{
									OIDCCredentialFormat: verifiable.JwtVCJsonLD,
								},
							},
						},
					}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					nil, errors.New("invalid json"))

				mocks.eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
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
			setup: func(mocks *mocks) {
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					nil, errors.New("well known service error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
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
			setup: func(mocks *mocks) {
				mocks.transactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).Return(
					nil, fmt.Errorf("store error"))

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "store error")
			},
		},
		{
			name: "Unsupported grant type",
			setup: func(mocks *mocks) {
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "PermanentResidentCard",
						},
					},
				}

				profile = &profileapi.Issuer{
					Active:     true,
					SigningDID: &profileapi.SigningDID{},
					OIDCConfig: &profileapi.OIDCConfig{
						GrantTypesSupported: []string{oidc4ci.GrantTypePreAuthorizedCode},
					},
					VCConfig: &profileapi.VCConfig{},
					CredentialMetaData: &profileapi.CredentialMetaData{
						CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{
							"PermanentResidentCard": {
								CredentialDefinition: &profileapi.CredentialDefinition{
									Type: []string{"PermanentResidentCard"},
								},
							},
						},
					},
					CredentialTemplates: []*profileapi.CredentialTemplate{
						{
							ID:   "PermanentResidentCard",
							Type: "PermanentResidentCard",
						},
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "unsupported grant type authorization_code")
			},
		},
		{
			name: "Unexpected grant type",
			setup: func(mocks *mocks) {
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 "unexpected_gt",
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "PermanentResidentCard",
						},
					},
				}

				profile = &profileapi.Issuer{
					Active:   true,
					VCConfig: &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "unexpected grant_type supplied unexpected_gt")
			},
		},
		{
			name: "Error OIDC config is empty",
			setup: func(mocks *mocks) {
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "PermanentResidentCard",
						},
					},
				}

				profile = &profileapi.Issuer{
					Active:   true,
					VCConfig: &profileapi.VCConfig{},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "authorized code flow not supported")
			},
		},
		{
			name: "Unsupported scope",
			setup: func(mocks *mocks) {
				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), issuerWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					OpState:                   "eyJhbGciOiJSU0Et",
					GrantType:                 oidc4ci.GrantTypeAuthorizationCode,
					Scope:                     []string{"invalid_value"},
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "unsupported scope invalid_value")
			},
		},
		{
			name: "Error because of claims validation error",
			setup: func(mocks *mocks) {
				initialOpState := "eyJhbGciOiJSU0Et"
				claimData := map[string]interface{}{
					"name":   1,
					"wife":   "Jane Doe",
					"degree": "MIT",
				}

				mocks.wellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).Times(0)

				mocks.jsonSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("validation error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            initialOpState,
					UserPinRequired:    false,
					GrantType:          oidc4ci.GrantTypePreAuthorizedCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimData:            claimData,
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "validation error")
				require.Nil(t, resp)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mocks{
				transactionStore:    NewMockTransactionStore(gomock.NewController(t)),
				wellKnownService:    NewMockWellKnownService(gomock.NewController(t)),
				claimDataStore:      NewMockClaimDataStore(gomock.NewController(t)),
				eventService:        NewMockEventService(gomock.NewController(t)),
				pinGenerator:        NewMockPinGenerator(gomock.NewController(t)),
				crypto:              NewMockDataProtector(gomock.NewController(t)),
				jsonSchemaValidator: NewMockJSONSchemaValidator(gomock.NewController(t)),
				documentLoader:      jsonld.NewDefaultDocumentLoader(http.DefaultClient),
				wellKnown:           NewMockwellKnownProvider(gomock.NewController(t)),
			}

			tt.setup(m)

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore:    m.transactionStore,
				ClaimDataStore:      m.claimDataStore,
				WellKnownService:    m.wellKnownService,
				IssuerVCSPublicHost: issuerVCSPublicHost,
				EventService:        m.eventService,
				EventTopic:          spi.IssuerEventTopic,
				PinGenerator:        m.pinGenerator,
				DataProtector:       m.crypto,
				JSONSchemaValidator: m.jsonSchemaValidator,
				DocumentLoader:      m.documentLoader,
				WellKnownProvider:   m.wellKnown,
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

		got := svc.GetCredentialsExpirationTime(&expected, nil)

		assert.Equal(t, expected, got)
	})

	t.Run("in template", func(t *testing.T) {
		svc, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		expected := time.Now().UTC().Add(60 * time.Hour)

		got := svc.GetCredentialsExpirationTime(nil,
			&profileapi.CredentialTemplate{
				CredentialDefaultExpirationDuration: lo.ToPtr(60 * time.Hour),
			},
		)

		assert.Equal(t, got.Truncate(time.Hour*24), expected.Truncate(time.Hour*24))
	})

	t.Run("default", func(t *testing.T) {
		svc, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		expected := time.Now().UTC().Add(365 * 24 * time.Hour)

		got := svc.GetCredentialsExpirationTime(nil,
			&profileapi.CredentialTemplate{
				CredentialDefaultExpirationDuration: nil,
			},
		)

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
		kmsRegistry          = NewMockKMSRegistry(gomock.NewController(t))
		cryptoJWTSigner      = NewMockCryptoJWTSigner(gomock.NewController(t))
		documentLoader       = NewMockDocumentLoader(gomock.NewController(t))
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
			name: "JWT disabled - Success with reference store",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
									},
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
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL,
					"https://wallet.example.com/initiate_issuance?"+
						"credential_offer_uri=https%3A%2F%2Fremote_url%2Ffile.jwt")
				require.Equal(t, oidc4ci.ContentTypeApplicationJSON, resp.ContentType)
			},
		},
		{
			name: "JWT disabled - Fail uploading to remote",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
									},
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
					&oidc4ci.IssuerIDPOIDCConfiguration{}, nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profile = &testProfile
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.ErrorContains(t, err, "fail uploading to remote")
				require.Nil(t, resp)
			},
		},
		{
			name: "JWT enabled - Success with reference store",
			setup: func() {
				const mockSignedCredentialOfferJWT = "aa.bb.cc"

				mockTransactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
									},
								},
							},
						}, nil
					})
				referenceStore = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
				referenceStore.EXPECT().CreateJWT(gomock.Any(), mockSignedCredentialOfferJWT).
					DoAndReturn(func(
						ctx context.Context,
						signedCredentialOffer string,
					) (string, error) {
						return "https://remote_url/file.jwt", nil
					})

				mockWellKnownService.EXPECT().GetOIDCConfiguration(gomock.Any(), walletWellKnownURL).Return(
					&oidc4ci.IssuerIDPOIDCConfiguration{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionInitiated)

						return nil
					})

				kmsConfig := &vcskms.Config{
					KMSType:           vcskms.AWS,
					Endpoint:          "example.com",
					Region:            "us-central-1",
					AliasPrefix:       "AliasPrefix",
					SecretLockKeyPath: "SecretLockKeyPath",
					DBType:            "DBType",
					DBURL:             "DBURL",
					DBName:            "DBName",
				}

				kmsRegistry.EXPECT().GetKeyManager(kmsConfig).Return(nil, nil)

				cryptoJWTSigner.EXPECT().NewJWTSigned(gomock.Any(), gomock.Any()).
					DoAndReturn(func(claims interface{}, signerData *vc.Signer) (string, error) {
						assert.Equal(t, &vc.Signer{
							KeyType:       "ECDSASecp256k1DER",
							KMSKeyID:      "",
							KMS:           nil,
							SignatureType: "JsonWebSignature2020",
							Creator:       "",
						}, signerData)

						credentialOfferClaims, ok := claims.(*oidc4ci.JWTCredentialOfferClaims)
						assert.True(t, ok)

						assert.Equal(t, "did:orb:anything", credentialOfferClaims.Issuer)
						assert.Equal(t, "did:orb:anything", credentialOfferClaims.Subject)
						assert.False(t, credentialOfferClaims.IssuedAt.Time().IsZero())

						return mockSignedCredentialOfferJWT, nil
					})

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profileSignedCredentialOfferSupported := testProfile
				profileSignedCredentialOfferSupported.KMSConfig = kmsConfig
				profileSignedCredentialOfferSupported.OIDCConfig = &profileapi.OIDCConfig{
					SignedCredentialOfferSupported: true,
					GrantTypesSupported:            []string{oidc4ci.GrantTypeAuthorizationCode},
				}

				profile = &profileSignedCredentialOfferSupported
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL,
					"https://wallet.example.com/initiate_issuance?"+
						"credential_offer_uri=https%3A%2F%2Fremote_url%2Ffile.jwt")
				require.Equal(t, oidc4ci.ContentTypeApplicationJWT, resp.ContentType)
			},
		},
		{
			name: "JWT enabled - KMS registry error",
			setup: func() {
				referenceStore = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
				mockWellKnownService = NewMockWellKnownService(gomock.NewController(t))
				cryptoJWTSigner = NewMockCryptoJWTSigner(gomock.NewController(t))

				mockTransactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
									},
								},
							},
						}, nil
					})

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

				kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).Return(nil, errors.New("some error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profileSignedCredentialOfferSupported := testProfile
				profileSignedCredentialOfferSupported.OIDCConfig = &profileapi.OIDCConfig{
					SignedCredentialOfferSupported: true,
					GrantTypesSupported:            []string{oidc4ci.GrantTypeAuthorizationCode},
				}

				profile = &profileSignedCredentialOfferSupported
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorContains(t, err, "get kms:")
			},
		},
		{
			name: "JWT enabled - crypto signer error",
			setup: func() {
				referenceStore = NewMockCredentialOfferReferenceStore(gomock.NewController(t))
				mockWellKnownService = NewMockWellKnownService(gomock.NewController(t))

				mockTransactionStore.EXPECT().Create(gomock.Any(), int32(0), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						profileTransactionDataTTL int32,
						data *issuecredential.TransactionData,
					) (*issuecredential.Transaction, error) {
						assert.Equal(t, issuecredential.TransactionStateIssuanceInitiated, data.State)

						return &issuecredential.Transaction{
							ID: "txID",
							TransactionData: issuecredential.TransactionData{
								CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
									{
										OIDCCredentialFormat: verifiable.JwtVCJsonLD,
										CredentialTemplate: &profileapi.CredentialTemplate{
											ID: "templateID",
										},
									},
								},
							},
						}, nil
					})

				eventService.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

				kmsConfig := &vcskms.Config{
					KMSType:           vcskms.AWS,
					Endpoint:          "example.com",
					Region:            "us-central-1",
					AliasPrefix:       "AliasPrefix",
					SecretLockKeyPath: "SecretLockKeyPath",
					DBType:            "DBType",
					DBURL:             "DBURL",
					DBName:            "DBName",
				}

				kmsRegistry.EXPECT().GetKeyManager(kmsConfig).Return(nil, nil)

				cryptoJWTSigner.EXPECT().NewJWTSigned(gomock.Any(), gomock.Any()).Return("", errors.New("some error"))

				issuanceReq = &oidc4ci.InitiateIssuanceRequest{
					ClientWellKnownURL: walletWellKnownURL,
					OpState:            "eyJhbGciOiJSU0Et",
					GrantType:          oidc4ci.GrantTypeAuthorizationCode,
					CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
						{
							ClaimEndpoint:        "https://vcs.pb.example.com/claim",
							CredentialTemplateID: "templateID",
						},
					},
				}

				profileSignedCredentialOfferSupported := testProfile
				profileSignedCredentialOfferSupported.KMSConfig = kmsConfig
				profileSignedCredentialOfferSupported.OIDCConfig = &profileapi.OIDCConfig{
					SignedCredentialOfferSupported: true,
					GrantTypesSupported:            []string{oidc4ci.GrantTypeAuthorizationCode},
				}

				profile = &profileSignedCredentialOfferSupported
			},
			check: func(t *testing.T, resp *oidc4ci.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorContains(t, err, "sign credential offer:")
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
				KMSRegistry:                   kmsRegistry,
				CryptoJWTSigner:               cryptoJWTSigner,
				EventTopic:                    spi.IssuerEventTopic,
				DocumentLoader:                documentLoader,
			})
			require.NoError(t, err)

			resp, err := svc.InitiateIssuance(context.Background(), issuanceReq, profile)
			tt.check(t, resp, err)
		})
	}
}
