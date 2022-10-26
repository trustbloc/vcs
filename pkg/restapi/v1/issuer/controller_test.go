/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/restapiclient"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

const (
	orgID = "orgID1"
)

var (
	//go:embed testdata/sample_vc.jsonld
	sampleVCJsonLD string
	//go:embed testdata/sample_vc.jwt
	sampleVCJWT string
)

// nolint:gochecknoglobals
var ariesSupportedKeyTypes = []kms.KeyType{
	kms.ED25519Type,
	kms.X25519ECDHKWType,
	kms.ECDSASecp256k1TypeIEEEP1363,
	kms.ECDSAP256TypeDER,
	kms.ECDSAP384TypeDER,
	kms.RSAPS256Type,
	kms.BLS12381G2Type,
}

func TestController_PostIssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
	mockIssueCredentialSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, nil)

	t.Run("Success JSON-LD", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		c := echoContext(withRequestBody([]byte(sampleVCJsonLD)))

		err := controller.PostIssueCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Jwt,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		c := echoContext(withRequestBody([]byte(sampleVCJWT)))

		err := controller.PostIssueCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(&Config{})
		c := echoContext(withRequestBody([]byte("abc")))
		err := controller.PostIssueCredentials(c, "testId")

		requireValidationError(t, "invalid-value", "requestBody", err)
	})
}

func TestController_IssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
	mockIssueCredentialSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return(&verifiable.Credential{}, nil)

	t.Run("Success JSON-LD", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		c := echoContext(withRequestBody([]byte(sampleVCJsonLD)))

		var body IssueCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		verifiableCredentials, err := controller.issueCredential(c, &body, "testId")
		require.NotNil(t, verifiableCredentials)
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Jwt,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		c := echoContext(withRequestBody([]byte(sampleVCJWT)))

		var body IssueCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		verifiableCredentials, err := controller.issueCredential(c, &body, "testId")
		require.NotNil(t, verifiableCredentials)
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name                      string
			getCtx                    func() echo.Context
			getProfileSvc             func() profileService
			getIssueCredentialService func() issueCredentialService
		}{
			{
				name: "Missing authorization",
				getCtx: func() echo.Context {
					ctx := echoContext(withRequestBody([]byte(sampleVCJsonLD)))
					ctx.Request().Header.Set("X-User", "")
					return ctx
				},
				getProfileSvc: func() profileService {
					return nil
				},
				getIssueCredentialService: func() issueCredentialService {
					return nil
				},
			},
			{
				name: "Profile service error",
				getCtx: func() echo.Context {
					return echoContext(withRequestBody([]byte(sampleVCJsonLD)))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile("testId").Times(1).
						Return(nil, errors.New("some error"))
					return failedMockProfileSvc
				},
				getIssueCredentialService: func() issueCredentialService {
					return nil
				},
			},
			{
				name: "Validate credential error",
				getCtx: func() echo.Context {
					return echoContext(withRequestBody([]byte(`{"credential":"","options":{}}`)))
				},
				getProfileSvc: func() profileService {
					mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
						Return(&profileapi.Issuer{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &profileapi.VCConfig{
								Format: vcsverifiable.Ldp,
							},
						}, nil)

					return mockProfileSvc
				},
				getIssueCredentialService: func() issueCredentialService {
					return nil
				},
			},
			{
				name: "Validate credential options error",
				getCtx: func() echo.Context {
					return echoContext(withRequestBody(
						[]byte(`{"credential":"","options":{"credentialStatus":{"type":"statusPurpose"}}}`)))
				},
				getProfileSvc: func() profileService {
					mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
						Return(&profileapi.Issuer{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &profileapi.VCConfig{
								Format: vcsverifiable.Ldp,
							},
						}, nil)
					return mockProfileSvc
				},
				getIssueCredentialService: func() issueCredentialService {
					return nil
				},
			},
			{
				name: "Issue credential error",
				getCtx: func() echo.Context {
					return echoContext(withRequestBody([]byte(sampleVCJsonLD)))
				},
				getProfileSvc: func() profileService {
					mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
						Return(&profileapi.Issuer{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &profileapi.VCConfig{
								Format: vcsverifiable.Ldp,
							},
						}, nil)
					return mockProfileSvc
				},
				getIssueCredentialService: func() issueCredentialService {
					mockFailedIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
					mockFailedIssueCredentialSvc.EXPECT().IssueCredential(
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).AnyTimes().
						Return(nil, errors.New("some error"))
					return mockFailedIssueCredentialSvc
				},
			},
		}

		for _, testCase := range tests {
			t.Run(testCase.name, func(t *testing.T) {
				controller := NewController(&Config{
					ProfileSvc:             testCase.getProfileSvc(),
					DocumentLoader:         testutil.DocumentLoader(t),
					IssueCredentialService: testCase.getIssueCredentialService(),
				})
				ctx := testCase.getCtx()
				var body IssueCredentialData
				err := util.ReadBody(ctx, &body)
				require.NoError(t, err)
				verifiableCredentials, err := controller.issueCredential(ctx, &body, "testId")
				require.Nil(t, verifiableCredentials)
				require.Error(t, err)
			})
		}
	})
}

func TestController_AuthFailed(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Issuer{OrganizationID: orgID, SigningDID: &profileapi.SigningDID{}}, nil)

	t.Run("No token", func(t *testing.T) {
		c := echoContext(withOrgID(""), withRequestBody([]byte(sampleVCJWT)))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.PostIssueCredentials(c, "testId")
		requireAuthError(t, err)
	})

	t.Run("Invalid org id", func(t *testing.T) {
		c := echoContext(withOrgID("orgID2"), withRequestBody([]byte(sampleVCJWT)))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.PostIssueCredentials(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})
}

func Test_validateIssueCredOptions(t *testing.T) {
	type args struct {
		options *IssueCredentialOptions
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name: "Nil options",
			args: args{
				options: nil,
			},
			wantLen: 0,
			wantErr: false,
		},
		{
			name: "Not supported credential status type",
			args: args{
				options: &IssueCredentialOptions{
					CredentialStatus: &CredentialStatusOpt{
						Type: credentialstatus.StatusListCredential,
					},
				},
			},
			wantLen: 0,
			wantErr: true,
		},
		{
			name: "Invalid created time",
			args: args{
				options: &IssueCredentialOptions{
					CredentialStatus: &CredentialStatusOpt{
						Type: credentialstatus.StatusList2021Entry,
					},
					VerificationMethod: lo.ToPtr("did:trustbloc:abc"),
					Created:            lo.ToPtr("02 Jan 06 15:04 MST"),
				},
			},
			wantLen: 0,
			wantErr: true,
		},
		{
			name: "OK",
			args: args{
				options: &IssueCredentialOptions{
					CredentialStatus: &CredentialStatusOpt{
						Type: credentialstatus.StatusList2021Entry,
					},
					VerificationMethod: lo.ToPtr("did:trustbloc:abc"),
					Created:            lo.ToPtr("1979-05-27T07:32:00Z"),
					Challenge:          lo.ToPtr("challenge"),
					Domain:             lo.ToPtr("domain"),
				},
			},
			wantLen: 4,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateIssueCredOptions(tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIssueCredOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantLen != len(got) {
				t.Errorf("validateIssueCredOptions() got = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestController_PostIssuerProfilesProfileIDInteractionsInitiateOidc(t *testing.T) {
	issuerProfile := &profileapi.Issuer{
		OrganizationID: orgID,
		ID:             "profileID",
		Active:         true,
		OIDCConfig:     &profileapi.OIDC4VCConfig{},
		CredentialTemplates: []*verifiable.Credential{
			{
				ID: "templateID",
			},
		},
	}

	req, err := json.Marshal(&InitiateOIDC4VCRequest{
		CredentialTemplateId:      lo.ToPtr("templateID"),
		ClientInitiateIssuanceUrl: lo.ToPtr("https://wallet.example.com/initiate_issuance"),
		ClientWellknown:           lo.ToPtr("https://wallet.example.com/.well-known/openid-configuration"),
		OpState:                   lo.ToPtr("eyJhbGciOiJSU0Et"),
		ClaimEndpoint:             lo.ToPtr("https://vcs.pb.example.com/claim"),
		GrantType:                 lo.ToPtr("authorization_code"),
		Scope:                     lo.ToPtr([]string{"openid"}),
		ResponseType:              lo.ToPtr("token"),
	})
	require.NoError(t, err)

	info := &oidc4vc.InitiateIssuanceResponse{
		InitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
		TxID:                "txID",
	}

	var (
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		mockOIDC4VCSvc = NewMockOIDC4VCService(gomock.NewController(t))
		c              echo.Context
	)

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(issuerProfile, nil)
		mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(info, nil)

		controller := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4VCService: mockOIDC4VCSvc,
		})

		c = echoContext(withRequestBody(req))

		err = controller.PostIssuerProfilesProfileIDInteractionsInitiateOidc(c, "profileID")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func()
			check func(t *testing.T, err error)
		}{
			{
				name: "Missing authorization",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(0)
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req), withOrgID(""))
				},
				check: func(t *testing.T, err error) {
					requireAuthError(t, err)
				},
			},
			{
				name: "Invalid profile",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(issuerProfile, nil)
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req), withOrgID("invalid"))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile with given id")
				},
			},
			{
				name: "Profile does not exist in the underlying storage",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, errors.New("not found"))
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile with given id")
				},
			},
			{
				name: "Get profile error",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, errors.New("get profile error"))
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "get profile error")
				},
			},
			{
				name: "Profile is not active",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(&profileapi.Issuer{
						OrganizationID: orgID,
						ID:             "profileID",
						Active:         false,
						OIDCConfig:     &profileapi.OIDC4VCConfig{},
					}, nil)

					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile should be active")
				},
			},
			{
				name: "OIDC is not configured",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(&profileapi.Issuer{
						OrganizationID: orgID,
						ID:             "profileID",
						Active:         true,
					}, nil)

					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "OIDC not configured")
				},
			},
			{
				name: "Credential template ID is required",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(issuerProfile, nil)
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oidc4vc.ErrCredentialTemplateIDRequired) //nolint:lll

					r, marshalErr := json.Marshal(&InitiateOIDC4VCRequest{})
					require.NoError(t, marshalErr)

					c = echoContext(withRequestBody(r))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "credential template ID is required")
				},
			},
			{
				name: "Credential template not found",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(issuerProfile, nil)
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oidc4vc.ErrCredentialTemplateNotFound) //nolint:lll

					r, marshalErr := json.Marshal(&InitiateOIDC4VCRequest{})
					require.NoError(t, marshalErr)

					c = echoContext(withRequestBody(r))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "credential template not found")
				},
			},
			{
				name: "Service error",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(issuerProfile, nil)
					mockOIDC4VCSvc.EXPECT().InitiateInteraction(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("service error")) //nolint:lll
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "service error")
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tt.setup()

				controller := NewController(&Config{
					ProfileSvc:     mockProfileSvc,
					OIDC4VCService: mockOIDC4VCSvc,
				})

				err = controller.PostIssuerProfilesProfileIDInteractionsInitiateOidc(c, "profileID")
				tt.check(t, err)
			})
		}
	})
}

func TestController_PostCredentialsStatus(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
	mockVCStatusManager.EXPECT().UpdateVCStatus(
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig:       &profileapi.VCConfig{},
				SigningDID:     &profileapi.SigningDID{},
			}, nil)

		controller := NewController(&Config{
			KMSRegistry:     kmsRegistry,
			ProfileSvc:      mockProfileSvc,
			DocumentLoader:  testutil.DocumentLoader(t),
			VcStatusManager: mockVCStatusManager,
		})

		c := echoContext(withRequestBody(
			[]byte(`{"credentialID": "1","credentialStatus":{"type":"StatusList2021Entry"}}`)))

		err := controller.PostCredentialsStatus(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(&Config{})
		c := echoContext(withRequestBody([]byte("abc")))
		err := controller.PostCredentialsStatus(c, "testId")

		requireValidationError(t, "invalid-value", "requestBody", err)
	})
}

func TestController_UpdateCredentialStatus(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig:       &profileapi.VCConfig{},
				SigningDID:     &profileapi.SigningDID{},
			}, nil)

		kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, nil)

		mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		mockVCStatusManager.EXPECT().UpdateVCStatus(
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		controller := NewController(&Config{
			KMSRegistry:     kmsRegistry,
			ProfileSvc:      mockProfileSvc,
			DocumentLoader:  testutil.DocumentLoader(t),
			VcStatusManager: mockVCStatusManager,
		})

		body := &UpdateCredentialStatusRequest{
			CredentialID: "1",
			CredentialStatus: CredentialStatus{
				Type: "StatusList2021Entry",
			},
		}

		err := controller.updateCredentialStatus(echoContext(), body, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		type fields struct {
			getProfileSvc      func() profileService
			getVCStatusManager func() vcStatusManager
			getKMSRegistry     func() kmsRegistry
		}
		type args struct {
			ctx       echo.Context
			body      *UpdateCredentialStatusRequest
			profileID string
		}
		tests := []struct {
			name    string
			fields  fields
			args    args
			wantErr string
		}{
			{
				name: "Missing authorization",
				fields: fields{
					getProfileSvc: func() profileService {
						return nil
					},
					getVCStatusManager: func() vcStatusManager {
						return nil
					},
					getKMSRegistry: func() kmsRegistry {
						return nil
					},
				},
				args: args{
					ctx:       echoContext(withOrgID("")),
					body:      &UpdateCredentialStatusRequest{},
					profileID: "test",
				},
				wantErr: "missing authorization",
			},
			{
				name: "Profile doesn't exist",
				fields: fields{
					getProfileSvc: func() profileService {
						mockProfileSvc := NewMockProfileService(gomock.NewController(t))
						mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
							Return(nil, errors.New("not found"))
						return mockProfileSvc
					},
					getVCStatusManager: func() vcStatusManager {
						return nil
					},
					getKMSRegistry: func() kmsRegistry {
						return nil
					},
				},
				args: args{
					ctx:       echoContext(),
					body:      &UpdateCredentialStatusRequest{},
					profileID: "testId",
				},
				wantErr: "profile with given id testId, dosn't exists",
			},
			{
				name: "KMS registry error",
				fields: fields{
					getProfileSvc: func() profileService {
						mockProfileSvc := NewMockProfileService(gomock.NewController(t))
						mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
							Return(&profileapi.Issuer{
								OrganizationID: orgID,
								ID:             "testId",
								VCConfig:       &profileapi.VCConfig{},
								SigningDID:     &profileapi.SigningDID{},
							}, nil)
						return mockProfileSvc
					},
					getKMSRegistry: func() kmsRegistry {
						kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
						kmsRegistry.EXPECT().GetKeyManager(
							gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))
						return kmsRegistry
					},
					getVCStatusManager: func() vcStatusManager {
						return nil
					},
				},
				args: args{
					ctx:       echoContext(),
					body:      &UpdateCredentialStatusRequest{},
					profileID: "testId",
				},
				wantErr: "failed to get kms",
			},
			{
				name: "Not supported cred type",
				fields: fields{
					getProfileSvc: func() profileService {
						mockProfileSvc := NewMockProfileService(gomock.NewController(t))
						mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
							Return(&profileapi.Issuer{
								OrganizationID: orgID,
								ID:             "testId",
								VCConfig:       &profileapi.VCConfig{},
								SigningDID:     &profileapi.SigningDID{},
							}, nil)
						return mockProfileSvc
					},
					getKMSRegistry: func() kmsRegistry {
						kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
						kmsRegistry.EXPECT().GetKeyManager(
							gomock.Any()).AnyTimes().Return(nil, nil)
						return kmsRegistry
					},
					getVCStatusManager: func() vcStatusManager {
						return nil
					},
				},
				args: args{
					ctx: echoContext(),
					body: &UpdateCredentialStatusRequest{
						CredentialStatus: CredentialStatus{
							Type: "invalid",
						},
					},
					profileID: "testId",
				},
				wantErr: "credential status invalid not supported",
			},
			{
				name: "UpdateVCStatus error",
				fields: fields{
					getProfileSvc: func() profileService {
						mockProfileSvc := NewMockProfileService(gomock.NewController(t))
						mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
							Return(&profileapi.Issuer{
								OrganizationID: orgID,
								ID:             "testId",
								VCConfig:       &profileapi.VCConfig{},
								SigningDID:     &profileapi.SigningDID{},
							}, nil)
						return mockProfileSvc
					},
					getKMSRegistry: func() kmsRegistry {
						kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
						kmsRegistry.EXPECT().GetKeyManager(
							gomock.Any()).AnyTimes().Return(nil, nil)
						return kmsRegistry
					},
					getVCStatusManager: func() vcStatusManager {
						mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
						mockVCStatusManager.EXPECT().UpdateVCStatus(
							gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
							Return(errors.New("some error"))
						return mockVCStatusManager
					},
				},
				args: args{
					ctx: echoContext(),
					body: &UpdateCredentialStatusRequest{
						CredentialStatus: CredentialStatus{
							Type: "StatusList2021Entry",
						},
					},
					profileID: "testId",
				},
				wantErr: "system-error[VCStatusManager, UpdateVCStatus]: some error",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c := &Controller{
					profileSvc:      tt.fields.getProfileSvc(),
					vcStatusManager: tt.fields.getVCStatusManager(),
					kmsRegistry:     tt.fields.getKMSRegistry(),
				}
				err := c.updateCredentialStatus(tt.args.ctx, tt.args.body, tt.args.profileID)
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})
}

func TestPrepareClaimDataAuth(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := NewMockOIDC4VCService(gomock.NewController(t))
		mock.EXPECT().PrepareClaimDataAuthZ(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req restapiclient.PrepareClaimDataAuthorizationRequest,
			) (*restapiclient.PrepareClaimDataAuthorizationResponse, error) {
				assert.Equal(t, "123", req.OpState)

				return &restapiclient.PrepareClaimDataAuthorizationResponse{
					RedirectURI: "https://trust/redirect",
				}, nil
			})
		c := &Controller{
			oidc4VCService: mock,
		}

		ctx := echoContext(withRequestBody([]byte(`{"op_state" : "123", "responder" : {"respond_mode": "query"}}`)))
		assert.NoError(t, c.PrepareClaimDataAuthzRequest(ctx))
	})

	t.Run("json decode error", func(t *testing.T) {
		c := &Controller{}
		ctx := echoContext(withRequestBody([]byte(`invalid json`)))
		assert.ErrorContains(t, c.PrepareClaimDataAuthzRequest(ctx), "invalid character")
	})
}

type options struct {
	orgID       string
	requestBody []byte
}

type contextOpt func(*options)

func withOrgID(orgID string) contextOpt {
	return func(o *options) {
		o.orgID = orgID
	}
}

func withRequestBody(body []byte) contextOpt {
	return func(o *options) {
		o.requestBody = body
	}
}

func echoContext(opts ...contextOpt) echo.Context {
	o := &options{
		orgID: orgID,
	}

	for _, fn := range opts {
		fn(o)
	}

	e := echo.New()

	var body io.Reader = http.NoBody

	if o.requestBody != nil {
		body = bytes.NewReader(o.requestBody)
	}

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	if o.orgID != "" {
		req.Header.Set("X-User", o.orgID)
	}

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func requireValidationError(t *testing.T, expectedCode resterr.ErrorCode, incorrectValueName string, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, expectedCode, actualErr.Code)
	require.Equal(t, incorrectValueName, actualErr.IncorrectValue)
	require.Error(t, actualErr.Err)
}

func requireAuthError(t *testing.T, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, resterr.Unauthorized, actualErr.Code)
}
