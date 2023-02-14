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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	orgID = "orgID1"
)

var (
	//go:embed testdata/sample_vc.jsonld
	sampleVCJsonLD string
	//go:embed testdata/sample_vc.jwt
	sampleVCJWT string
	//go:embed testdata/sample_vc_university_degree.jsonld
	sampleVCUniversityDegree []byte
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

	t.Run("Success LDP with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "test_template",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type:                                "VerifiedEmployee",
						CredentialDefaultExpirationDuration: lo.ToPtr(55 * time.Hour),
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			Credential:           nil,
			CredentialTemplateId: lo.ToPtr("test_template"),
			Options:              nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Success LDP without TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "test_template",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type: "VerifiedEmployee",
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			Credential: nil,
			Options:    nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Fail LDP without TemplateId and many templates", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "test_template",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type: "VerifiedEmployee",
					},
					{
						ID: "test_template2",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type: "VerifiedEmployee",
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			Credential: nil,
			Options:    nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.ErrorContains(t, err, "credential template should be specified")
	})

	t.Run("Fail LDP no template with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "test_template",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type: "VerifiedEmployee",
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			CredentialTemplateId: lo.ToPtr("random_template"),
			Credential:           nil,
			Options:              nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.ErrorContains(t, err, "credential template not found")
	})

	t.Run("Fail LDP no credential templates", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			CredentialTemplateId: lo.ToPtr("random_template"),
			Credential:           nil,
			Options:              nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.ErrorContains(t, err, "credential templates are not specified for profile")
	})

	t.Run("Success LDP no template with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID: "did:orb:bank_issuer",
				},
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "test_template",
						Contexts: []string{
							"https://www.w3.org/2018/credentials/v1",
						},
						Type: "VerifiedEmployee",
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
		})

		req := &IssueCredentialData{
			CredentialTemplateId: lo.ToPtr("test_template"),
			Credential:           nil,
			Options:              nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, "testId")
		require.ErrorContains(t, err, "no claims specified")
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
						[]byte(`{"credential":{
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
    },
    "issuer": {
      "id": "did:example:76e12ec712ebc6f1c221ebfeb1f"
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]
  },"options":{"credentialStatus":{"type":"statusPurpose"}}}`)))
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
		vcStatusListType vc.StatusType
		options          *IssueCredentialOptions
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
						Type: "unsupported",
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
						Type: string(vc.StatusList2021VCStatus),
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
				vcStatusListType: vc.StatusList2021VCStatus,
				options: &IssueCredentialOptions{
					CredentialStatus: &CredentialStatusOpt{
						Type: string(vc.StatusList2021VCStatus),
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
			got, err := validateIssueCredOptions(tt.args.options, &profileapi.Issuer{
				VCConfig: &profileapi.VCConfig{
					Status: profileapi.StatusConfig{
						Type: tt.args.vcStatusListType,
					},
				},
			})
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

func TestController_PostCredentialsStatus(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
	mockVCStatusManager.EXPECT().UpdateVCStatus(
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{
			KMSRegistry:     kmsRegistry,
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

func TestController_InitiateCredentialIssuance(t *testing.T) {
	issuerProfile := &profileapi.Issuer{
		OrganizationID: orgID,
		ID:             "profileID",
		Active:         true,
		OIDCConfig:     &profileapi.OIDC4CIConfig{},
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				ID: "templateID",
			},
		},
	}

	req, err := json.Marshal(&InitiateOIDC4CIRequest{
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

	resp := &oidc4ci.InitiateIssuanceResponse{
		InitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
		TxID:                "txID",
	}

	var (
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		mockOIDC4CISvc = NewMockOIDC4CIService(gomock.NewController(t))
		c              echo.Context
	)

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(issuerProfile, nil)
		mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(resp, nil)

		controller := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4CIService: mockOIDC4CISvc,
		})

		c = echoContext(withRequestBody(req))

		err = controller.InitiateCredentialIssuance(c, "profileID")
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "get profile error")
				},
			},
			{
				name: "Returned empty profile",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile with given id profileID, doesn't exist")
				},
			},
			{
				name: "Credential template ID is required",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(issuerProfile, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oidc4ci.ErrCredentialTemplateIDRequired) //nolint:lll

					r, marshalErr := json.Marshal(&InitiateOIDC4CIRequest{})
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oidc4ci.ErrCredentialTemplateNotFound) //nolint:lll

					r, marshalErr := json.Marshal(&InitiateOIDC4CIRequest{})
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
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("service error")) //nolint:lll
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
					OIDC4CIService: mockOIDC4CISvc,
				})

				err = controller.InitiateCredentialIssuance(c, "profileID")
				tt.check(t, err)
			})
		}
	})
}

func TestController_PushAuthorizationDetails(t *testing.T) {
	var (
		mockOIDC4CISvc = NewMockOIDC4CIService(gomock.NewController(t))
		req            string
	)

	t.Run("Success", func(t *testing.T) {
		mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(nil)

		controller := NewController(&Config{
			OIDC4CIService: mockOIDC4CISvc,
		})

		req = `{"op_state":"opState","authorization_details":{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}}` //nolint:lll
		c := echoContext(withRequestBody([]byte(req)))

		err := controller.PushAuthorizationDetails(c)
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func()
			check func(t *testing.T, err error)
		}{
			{
				name: "Invalid authorization_details type",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Times(0)

					req = `{"op_state":"opState","authorization_details":{"type":"invalid","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}}` //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "type should be 'openid_credential'")
				},
			},
			{
				name: "Credential type not supported",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						oidc4ci.ErrCredentialTypeNotSupported)

					req = `{"op_state":"opState","authorization_details":{"type":"openid_credential"}}`
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "credential type not supported")
				},
			},
			{
				name: "Credential format not supported",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						oidc4ci.ErrCredentialFormatNotSupported)

					req = `{"op_state":"opState","authorization_details":{"type":"openid_credential"}}`
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "credential format not supported")
				},
			},
			{
				name: "Service error",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						errors.New("service error"))

					req = `{"op_state":"opState","authorization_details":{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}}` //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "service error")
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tt.setup()

				controller := NewController(&Config{
					OIDC4CIService: mockOIDC4CISvc,
				})

				c := echoContext(withRequestBody([]byte(req)))

				err := controller.PushAuthorizationDetails(c)
				tt.check(t, err)
			})
		}
	})
}

func TestController_PrepareAuthorizationRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareClaimDataAuthorizationRequest,
			) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error) {
				assert.Equal(t, "123", req.OpState)

				return &oidc4ci.PrepareClaimDataAuthorizationResponse{}, nil
			},
		)

		mockProfileService := NewMockProfileService(gomock.NewController(t))
		mockProfileService.EXPECT().GetProfile(gomock.Any()).Return(&profileapi.Issuer{
			OIDCConfig: &profileapi.OIDC4CIConfig{},
		}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
			profileSvc:     mockProfileService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareAuthorizationRequest(ctx))
	})

	t.Run("invalid authorization_details.type", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":{"type":"invalid","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "authorization_details.type")
	})

	t.Run("invalid authorization_details.format", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"invalid","locations":[]}}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "authorization_details.format")
	})

	t.Run("service error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Return(
			nil, errors.New("service error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "service error")
	})

	t.Run("get profile failed", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareClaimDataAuthorizationRequest,
			) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error) {
				assert.Equal(t, "123", req.OpState)

				return &oidc4ci.PrepareClaimDataAuthorizationResponse{}, nil
			},
		)

		mockProfileService := NewMockProfileService(gomock.NewController(t))
		mockProfileService.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("get profile error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
			profileSvc:     mockProfileService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "get profile error")
	})
}

func TestController_StoreAuthZCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().StoreAuthorizationCode(gomock.Any(), opState, code).Return(oidc4ci.TxID("1234"), nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := fmt.Sprintf(`{"op_state":"%s","code":"%s"}`, opState, code) //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.StoreAuthorizationCodeRequest(ctx))
	})
	t.Run("invalid body", func(t *testing.T) {
		c := &Controller{}

		req := "{" //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.StoreAuthorizationCodeRequest(ctx), "unexpected EOF")
	})
}

func TestController_ExchangeAuthorizationCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState).Return(oidc4ci.TxID("1234"), nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := fmt.Sprintf(`{"op_state":"%s"}`, opState) //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.ExchangeAuthorizationCodeRequest(ctx))
	})

	t.Run("error from service", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState).
			Return(oidc4ci.TxID(""), errors.New("unexpected error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := fmt.Sprintf(`{"op_state":"%s"}`, opState) //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.ExchangeAuthorizationCodeRequest(ctx), "unexpected error")
	})

	t.Run("invalid body", func(t *testing.T) {
		c := &Controller{}

		req := "{" //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.ExchangeAuthorizationCodeRequest(ctx), "unexpected EOF")
	})
}

func TestController_ValidatePreAuthorizedCodeRequest(t *testing.T) {
	t.Run("success with pin", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "5432").
			Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					OpState: "random_op_state",
					Scope:   []string{"a", "b"},
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"pre-authorized_code":"1234", "user_pin" : "5432" }` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.ValidatePreAuthorizedCodeRequest(ctx))
	})

	t.Run("success without pin", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "").
			Return(&oidc4ci.Transaction{
				TransactionData: oidc4ci.TransactionData{
					OpState: "random_op_state",
					Scope:   []string{"a", "b"},
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"pre-authorized_code":"1234" }` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.ValidatePreAuthorizedCodeRequest(ctx))
	})

	t.Run("fail with pin", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "5432").
			Return(nil, errors.New("unexpected error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"pre-authorized_code":"1234", "user_pin" : "5432" }` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.ValidatePreAuthorizedCodeRequest(ctx), "unexpected error")
	})

	t.Run("invalid body", func(t *testing.T) {
		c := &Controller{}

		req := "{" //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.ValidatePreAuthorizedCodeRequest(ctx), "unexpected EOF")
	})
}

func TestController_PrepareCredential(t *testing.T) {
	sampleVC, err := verifiable.ParseCredential(
		sampleVCUniversityDegree,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "profileID",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, oidc4ci.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:  "profileID",
					Credential: sampleVC,
					Format:     vcsverifiable.Ldp,
					Retry:      false,
				}, nil
			},
		)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
		})

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareCredential(ctx))
	})

	t.Run("fail to access profile", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Return(nil, errors.New("get profile error"))

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, oidc4ci.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:  "profileID",
					Credential: sampleVC,
					Format:     vcsverifiable.Ldp,
					Retry:      false,
				}, nil
			},
		)

		c := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4CIService: mockOIDC4CIService,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "profile")
	})

	t.Run("fail to sign credential", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "profileID",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, oidc4ci.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:  "profileID",
					Credential: "invalid",
					Format:     vcsverifiable.Ldp,
					Retry:      false,
				}, nil
			},
		)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			OIDC4CIService:         mockOIDC4CIService,
			IssueCredentialService: mockIssueCredentialSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
		})

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "credential")
	})

	t.Run("invalid credential format", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"invalid"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "format")
	})

	t.Run("service error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(
			nil, errors.New("service error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "service error")
	})

	t.Run("service custom error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(
			nil, resterr.NewCustomError("rand-code", errors.New("rand")))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","type":"UniversityDegreeCredential","format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "rand-code[]: rand")
	})
}

func TestOpenIDConfigurationController(t *testing.T) {
	profileSvc := NewMockProfileService(gomock.NewController(t))
	profileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profileapi.Issuer{
		Name: "random_name",
		VCConfig: &profileapi.VCConfig{
			DIDMethod: "orb",
			KeyType:   "ECDSASecp256k1DER",
		},
		CredentialMetaData: &profileapi.CredentialMetaData{
			CredentialsSupported: map[string]map[string]interface{}{
				"VerifiedEmployee": {
					"id": "VerifiedEmployee_JWT",
				},
			},
		},
	}, nil)

	c := &Controller{
		externalHostURL: "https://localhost",
		profileSvc:      profileSvc,
	}

	assert.NoError(t, c.OpenidConfig(echoContext(), "123"))
}

func TestOpenIDIssuerConfigurationController(t *testing.T) {
	profileSvc := NewMockProfileService(gomock.NewController(t))
	profileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profileapi.Issuer{
		Name: "random_name",
		VCConfig: &profileapi.VCConfig{
			DIDMethod: "orb",
			KeyType:   "ECDSASecp256k1DER",
		},
		CredentialMetaData: &profileapi.CredentialMetaData{
			CredentialsSupported: map[string]map[string]interface{}{
				"VerifiedEmployee": {
					"id": "VerifiedEmployee_JWT",
				},
			},
		},
	}, nil)

	c := &Controller{
		externalHostURL: "https://localhost",
		profileSvc:      profileSvc,
	}

	assert.NoError(t, c.OpenidCredentialIssuerConfig(echoContext(), "123"))
}

func TestOpenIdIssuerConfiguration(t *testing.T) {
	host := "https://localhost"
	profileID := "123456"
	expected := &WellKnownOpenIDIssuerConfiguration{
		AuthorizationServer: "https://localhost/oidc/authorize",
		CredentialEndpoint:  "https://localhost/oidc/credential",
	}

	profileSvc := NewMockProfileService(gomock.NewController(t))
	profileSvc.EXPECT().GetProfile(profileID).Return(&profileapi.Issuer{
		Name: "random_name",
		VCConfig: &profileapi.VCConfig{
			DIDMethod: "orb",
			KeyType:   "ECDSASecp256k1DER",
		},
		CredentialMetaData: &profileapi.CredentialMetaData{
			CredentialsSupported: map[string]map[string]interface{}{
				"VerifiedEmployee": {
					"id": "VerifiedEmployee_JWT",
				},
			},
		},
	}, nil).Times(2)

	t.Run("with /", func(t *testing.T) {
		c := &Controller{
			externalHostURL: host,
			profileSvc:      profileSvc,
		}

		result, err := c.getOpenIDIssuerConfig(profileID)
		assert.NoError(t, err)
		assert.Equal(t, expected.AuthorizationServer, result.AuthorizationServer)
		assert.Equal(t, expected.CredentialEndpoint, result.CredentialEndpoint)

		assert.Equal(t, expected.CredentialEndpoint, result.CredentialEndpoint)
		assert.Equal(t, "random_name", *result.CredentialIssuer.Name)
		assert.Equal(t, "en-US", *result.CredentialIssuer.Locale)
		assert.Equal(t, "random_name", (*result.CredentialIssuer.Display)[0]["name"])
		assert.Equal(t, "en-US", (*result.CredentialIssuer.Display)[0]["locale"])

		assert.Len(t, result.CredentialsSupported, 1)

		meta := (result.CredentialsSupported)[0].(map[string]interface{}) //nolint
		assert.Equal(t, "VerifiedEmployee_JWT", meta["id"])
		assert.Equal(t, []string{"orb"}, meta["cryptographic_binding_methods_supported"])
		assert.Equal(t, []string{"ECDSASecp256k1DER"}, meta["cryptographic_suites_supported"])
	})

	t.Run("without /", func(t *testing.T) {
		c := &Controller{
			externalHostURL: host + "/",
			profileSvc:      profileSvc,
		}

		result, err := c.getOpenIDIssuerConfig(profileID)
		assert.NoError(t, err)
		assert.Equal(t, expected.AuthorizationServer, result.AuthorizationServer)
		assert.Equal(t, expected.CredentialEndpoint, result.CredentialEndpoint)
	})

	t.Run("profile error", func(t *testing.T) {
		svc := NewMockProfileService(gomock.NewController(t))
		svc.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("unexpected error"))

		c := &Controller{
			externalHostURL: host + "/",
			profileSvc:      svc,
		}

		result, err := c.getOpenIDIssuerConfig(profileID)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "unexpected error")
	})
}

func TestOpenIdConfiguration(t *testing.T) {
	host := "https://localhost"
	profileID := "123456"
	expected := &WellKnownOpenIDConfiguration{
		AuthorizationEndpoint:  "https://localhost/oidc/authorize",
		ResponseTypesSupported: []string{"code"},
		TokenEndpoint:          "https://localhost/oidc/token",
	}

	profileSvc := NewMockProfileService(gomock.NewController(t))
	profileSvc.EXPECT().GetProfile(profileID).Return(&profileapi.Issuer{
		Name: "random_name",
		VCConfig: &profileapi.VCConfig{
			DIDMethod: "orb",
			KeyType:   "ECDSASecp256k1DER",
		},
		CredentialMetaData: &profileapi.CredentialMetaData{
			CredentialsSupported: map[string]map[string]interface{}{
				"VerifiedEmployee": {
					"id": "VerifiedEmployee_JWT",
				},
			},
		},
	}, nil).Times(2)

	t.Run("with /", func(t *testing.T) {
		c := &Controller{
			externalHostURL: host,
			profileSvc:      profileSvc,
		}

		result, err := c.getOpenIDConfig(profileID)
		assert.NoError(t, err)
		assert.Equal(t, expected.AuthorizationEndpoint, result.AuthorizationEndpoint)
		assert.Equal(t, expected.TokenEndpoint, result.TokenEndpoint)
	})

	t.Run("without /", func(t *testing.T) {
		c := &Controller{
			externalHostURL: host + "/",
			profileSvc:      profileSvc,
		}

		result, err := c.getOpenIDConfig(profileID)
		assert.NoError(t, err)
		assert.Equal(t, expected.AuthorizationEndpoint, result.AuthorizationEndpoint)
		assert.Equal(t, expected.TokenEndpoint, result.TokenEndpoint)
	})

	t.Run("profile error", func(t *testing.T) {
		svc := NewMockProfileService(gomock.NewController(t))
		svc.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("unexpected error"))

		c := &Controller{
			externalHostURL: host + "/",
			profileSvc:      svc,
		}

		result, err := c.getOpenIDConfig(profileID)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "unexpected error")
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
