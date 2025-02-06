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
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timeutil "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

const (
	orgID          = "orgID1"
	profileID      = "testID"
	profileVersion = "v1.0"
)

var (
	//go:embed testdata/sample_vc.jsonld
	sampleVCJsonLD string
	//go:embed testdata/sample_vc_v2.jsonld
	sampleVCJsonLDV2 []byte
	//go:embed testdata/sample_vc.jwt
	sampleVCJWT string
	//go:embed testdata/sample_vc_university_degree.jsonld
	sampleVCUniversityDegree []byte
	//go:embed testdata/sample_vc_invalid_university_degree.jsonld
	sampleVCInvalidUniversityDegree []byte
	//go:embed testdata/universitydegree.schema.json
	universityDegreeSchema []byte
	//go:embed testdata/sample_invalid_vc_v2.jsonld
	sampleInvalidVCJsonLDV2 []byte
)

func TestController_PostIssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
	mockIssueCredentialSvc.EXPECT().IssueCredential(
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, nil)

	t.Run("Success JSON-LD", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
					Model:  vcsverifiable.V2_0,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		c := echoContext(withRequestBody([]byte(sampleVCJsonLD)))

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		c := echoContext(withRequestBody([]byte(sampleVCJWT)))

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Success LDP with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
						ID:                                  "test_template",
						Type:                                "VerifiedEmployee",
						CredentialDefaultExpirationDuration: lo.ToPtr(55 * time.Hour),
					},
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			Credential:            nil,
			CredentialTemplateId:  lo.ToPtr("test_template"),
			Options:               nil,
			CredentialDescription: lo.ToPtr("awesome"),
			CredentialName:        lo.ToPtr("awesome2"),
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("LDP with TemplateId - V2.0", func(t *testing.T) {
		issueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		issueCredentialSvc.EXPECT().IssueCredential(
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(
				ctx context.Context,
				credential *verifiable.Credential,
				profile *profileapi.Issuer,
				opts ...issuecredential.Opts,
			) (*verifiable.Credential, error) {
				return credential, nil
			},
		)

		issuerProfile := &profileapi.Issuer{
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
					ID:                                  "test_template",
					Type:                                "VerifiedEmployee",
					CredentialDefaultExpirationDuration: lo.ToPtr(55 * time.Hour),
				},
			},
		}

		req := &IssueCredentialData{
			Claims: lo.ToPtr(map[string]interface{}{
				"claim1": "value1",
			}),
			Credential:            nil,
			CredentialTemplateId:  lo.ToPtr("test_template"),
			Options:               nil,
			CredentialDescription: lo.ToPtr("awesome"),
			CredentialName:        lo.ToPtr("awesome2"),
		}

		t.Run("success", func(t *testing.T) {
			issuerProfile.VCConfig.Model = vcsverifiable.V2_0

			profileSvc := NewMockProfileService(gomock.NewController(t))
			profileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)

			controller := NewController(&Config{
				ProfileSvc:             profileSvc,
				DocumentLoader:         testutil.DocumentLoader(t),
				IssueCredentialService: issueCredentialSvc,
				Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
			})

			recorder := httptest.NewRecorder()

			b, _ := json.Marshal(req)
			c := echoContext(withRequestBody(b), withRecorder(recorder))

			err := controller.PostIssueCredentials(c, profileID, profileVersion)
			require.NoError(t, err)

			var vcDoc map[string]interface{}
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&vcDoc))
			require.NotEmpty(t, vcDoc["validFrom"])
			require.NotEmpty(t, vcDoc["validUntil"])
		})

		t.Run("unsupported model", func(t *testing.T) {
			issuerProfile.VCConfig.Model = "unsupported"

			profileSvc := NewMockProfileService(gomock.NewController(t))
			profileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)

			controller := NewController(&Config{
				ProfileSvc:             profileSvc,
				DocumentLoader:         testutil.DocumentLoader(t),
				IssueCredentialService: issueCredentialSvc,
				Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
			})

			b, _ := json.Marshal(req)
			c := echoContext(withRequestBody(b))

			err := controller.PostIssueCredentials(c, profileID, profileVersion)
			require.ErrorContains(t, err, "unsupported VC model")
		})

		t.Run("invalid context for model 2.0", func(t *testing.T) {
			issuerProfile.VCConfig.Model = vcsverifiable.V2_0
			issuerProfile.CredentialTemplates[0].Contexts = []string{"https://www.w3.org/2018/credentials/v1"}

			profileSvc := NewMockProfileService(gomock.NewController(t))
			profileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)

			controller := NewController(&Config{
				ProfileSvc:             profileSvc,
				DocumentLoader:         testutil.DocumentLoader(t),
				IssueCredentialService: issueCredentialSvc,
				Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
			})

			b, _ := json.Marshal(req)
			c := echoContext(withRequestBody(b))

			err := controller.PostIssueCredentials(c, profileID, profileVersion)
			require.ErrorContains(t, err, "invalid context for model w3c-vc-2.0")
		})
	})

	t.Run("Success LDP without TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
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

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Fail LDP without TemplateId and many templates", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
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

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.ErrorContains(t, err, "credential template should be specified")
	})

	t.Run("Fail LDP no template with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
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

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.ErrorContains(t, err, "credential template not found")
	})

	t.Run("Fail LDP no credential templates", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
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

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.ErrorContains(t, err, "credential templates are not specified for profile")
	})

	t.Run("Success LDP no template with TemplateId", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		req := &IssueCredentialData{
			CredentialTemplateId: lo.ToPtr("test_template"),
			Credential:           nil,
			Options:              nil,
		}

		b, _ := json.Marshal(req)
		c := echoContext(withRequestBody(b))

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		require.ErrorContains(t, err, "no claims specified")
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(&Config{Tracer: nooptracer.NewTracerProvider().Tracer("")})
		c := echoContext(withRequestBody([]byte("abc")))
		err := controller.PostIssueCredentials(c, profileID, profileVersion)

		requireValidationError(t, "invalid_credential_request", "requestBody", "", err)
	})
}

func TestController_IssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
	mockIssueCredentialSvc.EXPECT().IssueCredential(
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return(&verifiable.Credential{}, nil)

	t.Run("Success JSON-LD", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
					Model:  vcsverifiable.V2_0,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		c := echoContext(withRequestBody([]byte(sampleVCJsonLD)))

		var body IssueCredentialData

		err := c.Bind(&body)
		require.NoError(t, err)

		verifiableCredentials, err := controller.issueCredential(
			c.Request().Context(), orgID, &body, profileID, profileVersion)

		require.Nil(t, err)
		require.NotNil(t, verifiableCredentials)
	})

	t.Run("Success JSON-LD V2.0", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
			Return(&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &profileapi.VCConfig{
					Model:  vcsverifiable.V2_0,
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		controller := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			IssueCredentialService: mockIssueCredentialSvc,
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		c := echoContext(withRequestBody(sampleVCJsonLDV2))

		var body IssueCredentialData

		err := c.Bind(&body)
		require.NoError(t, err)

		verifiableCredentials, err := controller.issueCredential(
			c.Request().Context(), orgID, &body, profileID, profileVersion)

		require.Nil(t, err)
		require.NotNil(t, verifiableCredentials)
	})

	t.Run("Success JWT", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
			Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
		})

		c := echoContext(withRequestBody([]byte(sampleVCJWT)))

		var body IssueCredentialData

		err := c.Bind(&body)
		require.NoError(t, err)

		verifiableCredentials, err := controller.issueCredential(
			c.Request().Context(), orgID, &body, profileID, profileVersion)

		require.Nil(t, err)
		require.NotNil(t, verifiableCredentials)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name                      string
			getCtx                    func() echo.Context
			getProfileSvc             func() profileService
			getIssueCredentialService func() issueCredentialService
		}{
			{
				name: "Profile service error",
				getCtx: func() echo.Context {
					return echoContext(withRequestBody([]byte(sampleVCJsonLD)))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).
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
					Tracer:                 nooptracer.NewTracerProvider().Tracer(""),
				})
				ctx := testCase.getCtx()
				var body IssueCredentialData
				err := ctx.Bind(&body)
				require.NoError(t, err)
				verifiableCredentials, err := controller.issueCredential(
					ctx.Request().Context(), orgID, &body, profileID, profileVersion)
				require.Nil(t, verifiableCredentials)
				require.Error(t, err)
			})
		}
	})
}

func TestController_AuthFailed(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Issuer{OrganizationID: orgID, SigningDID: &profileapi.SigningDID{}}, nil)

	t.Run("No token", func(t *testing.T) {
		c := echoContext(withTenantID(""), withRequestBody([]byte(sampleVCJWT)))

		controller := NewController(&Config{
			ProfileSvc: mockProfileSvc,
			// KMSRegistry: kmsRegistry,
			Tracer: nooptracer.NewTracerProvider().Tracer(""),
		})

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		requireAuthError(t, err)
	})

	t.Run("Invalid org id", func(t *testing.T) {
		c := echoContext(withTenantID("orgID2"), withRequestBody([]byte(sampleVCJWT)))

		controller := NewController(&Config{
			ProfileSvc: mockProfileSvc,
			// KMSRegistry: kmsRegistry,
			Tracer: nooptracer.NewTracerProvider().Tracer(""),
		})

		err := controller.PostIssueCredentials(c, profileID, profileVersion)
		requireAuthError(t, err)
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
	mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))

	t.Run("Success", func(t *testing.T) {
		mockVCStatusManager.EXPECT().UpdateVCStatus(context.Background(), gomock.Any()).Times(1).Return(nil)

		controller := NewController(&Config{
			VcStatusManager: mockVCStatusManager,
		})

		c := echoContext(
			withOAuthClientRoles("revoker"),
			withRequestBody([]byte(`{"credentialID": "1","credentialStatus":{"type":"StatusList2021Entry"}}`)),
		)

		err := controller.PostCredentialsStatus(c)
		require.NoError(t, err)
	})

	t.Run("Failure: read body", func(t *testing.T) {
		controller := NewController(&Config{})
		c := echoContext(withRequestBody([]byte("abc")))
		err := controller.PostCredentialsStatus(c)

		requireValidationError(t,
			"bad_request", "requestBody", resterr.CredentialStatusMgmtComponent, err)
	})

	t.Run("Failure: missing role", func(t *testing.T) {
		controller := NewController(&Config{})

		c := echoContext(
			withOAuthClientRoles(""),
			withRequestBody([]byte(`{"credentialID": "1","credentialStatus":{"type":"StatusList2021Entry"}}`)),
		)

		err := controller.PostCredentialsStatus(c)
		requireAuthError(t, err)
	})

	t.Run("Failure: UpdateVCStatus error: regular error", func(t *testing.T) {
		mockVCStatusManager.
			EXPECT().
			UpdateVCStatus(context.Background(), gomock.Any()).Times(1).
			Return(errors.New("some error"))

		controller := NewController(&Config{
			VcStatusManager: mockVCStatusManager,
		})

		c := echoContext(
			withOAuthClientRoles("revoker"),
			withRequestBody([]byte(`{"credentialID": "1","credentialStatus":{"type":"StatusList2021Entry"}}`)),
		)

		err := controller.PostCredentialsStatus(c)
		requireValidationError(t,
			"bad_request", "", resterr.CredentialStatusMgmtComponent, err)
	})

	t.Run("Failure: UpdateVCStatus error: oidc4ci error", func(t *testing.T) {
		mockVCStatusManager.
			EXPECT().
			UpdateVCStatus(context.Background(), gomock.Any()).Times(1).
			Return(oidc4cierr.NewForbiddenError(errors.New("some error")))

		controller := NewController(&Config{
			VcStatusManager: mockVCStatusManager,
		})

		c := echoContext(
			withOAuthClientRoles("revoker"),
			withRequestBody([]byte(`{"credentialID": "1","credentialStatus":{"type":"StatusList2021Entry"}}`)),
		)

		err := controller.PostCredentialsStatus(c)
		requireValidationError(t,
			"forbidden", "", resterr.CredentialStatusMgmtComponent, err)
	})
}

func TestController_initiateCredentialIssuance_CompatibilityV1(t *testing.T) {
	issuerProfile := &profileapi.Issuer{
		OrganizationID: orgID,
		ID:             profileID,
		Version:        profileVersion,
		Active:         true,
		OIDCConfig:     &profileapi.OIDCConfig{},
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				ID: "templateID",
			},
		},
	}

	now := lo.ToPtr(time.Now().UTC())
	req, err := json.Marshal(&InitiateOIDC4CIRequest{
		ClaimData: lo.ToPtr(map[string]interface{}{
			"key": "value",
		}),
		ClaimEndpoint:             lo.ToPtr("https://vcs.pb.example.com/claim"),
		ClientInitiateIssuanceUrl: lo.ToPtr("https://wallet.example.com/initiate_issuance"),
		ClientWellknown:           lo.ToPtr("https://wallet.example.com/.well-known/openid-configuration"),
		CredentialDescription:     lo.ToPtr("description1"),
		CredentialExpiresAt:       now,
		CredentialName:            lo.ToPtr("name1"),
		CredentialTemplateId:      lo.ToPtr("templateID"),
		GrantType:                 lo.ToPtr(InitiateOIDC4CIRequestGrantTypeAuthorizationCode),
		OpState:                   lo.ToPtr("eyJhbGciOiJSU0Et"),
		ResponseType:              lo.ToPtr("token"),
		Scope:                     lo.ToPtr([]string{"openid"}),
		UserPinRequired:           lo.ToPtr(true),
		WalletInitiatedIssuance:   lo.ToPtr(true),
	})
	require.NoError(t, err)

	resp := &oidc4ci.InitiateIssuanceResponse{
		InitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
		TxID:                "txID",
	}

	var (
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		mockOIDC4CISvc = NewMockOIDC4CIService(gomock.NewController(t))
		mockEventSvc   = NewMockEventService(gomock.NewController(t))
		c              echo.Context
	)

	t.Run("Success", func(t *testing.T) {
		expectedInitiateIssuanceReq := &oidc4ci.InitiateIssuanceRequest{
			ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
			ClientWellKnownURL:        "https://wallet.example.com/.well-known/openid-configuration",
			GrantType:                 "authorization_code",
			ResponseType:              "token",
			Scope:                     []string{"openid"},
			OpState:                   "eyJhbGciOiJSU0Et",
			UserPinRequired:           true,
			WalletInitiatedIssuance:   true,
			CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
				{
					ClaimData: map[string]interface{}{
						"key": "value",
					},
					ClaimEndpoint:         "https://vcs.pb.example.com/claim",
					CredentialTemplateID:  "templateID",
					CredentialExpiresAt:   now,
					CredentialName:        "name1",
					CredentialDescription: "description1",
					ComposeCredential:     nil,
				},
			},
		}

		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
		mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), expectedInitiateIssuanceReq, issuerProfile).
			Times(1).Return(resp, nil)
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

		controller := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4CIService: mockOIDC4CISvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.IssuerEventTopic,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		c = echoContext(withRequestBody(req))

		err = controller.InitiateCredentialIssuance(c, profileID, profileVersion)
		require.NoError(t, err)
	})
}

func TestController_ComposeIssuance(t *testing.T) {
	issuerProfile := &profileapi.Issuer{
		OrganizationID: orgID,
		ID:             profileID,
		Version:        profileVersion,
		Active:         true,
		OIDCConfig:     &profileapi.OIDCConfig{},
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				ID: "templateID",
			},
		},
	}

	var (
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		mockOIDC4CISvc = NewMockOIDC4CIService(gomock.NewController(t))
		mockEventSvc   = NewMockEventService(gomock.NewController(t))
		c              echo.Context
	)

	t.Run("Success", func(t *testing.T) {
		expectedCred := map[string]interface{}{
			"a": "b",
		}
		req, err := json.Marshal(&InitiateOIDC4CIComposeRequest{
			ClientInitiateIssuanceUrl: lo.ToPtr("https://wallet.example.com/initiate_issuance"),
			ClientWellknown:           lo.ToPtr("https://wallet.example.com/.well-known/openid-configuration"),
			Compose: lo.ToPtr([]InitiateIssuanceCredentialConfigurationCompose{
				{
					CredentialOverrideId: lo.ToPtr("abc"),
					Credential:           &expectedCred,
				},
			}),
		})

		require.NoError(t, err)

		resp := &oidc4ci.InitiateIssuanceResponse{
			InitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
			TxID:                "txID",
		}

		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
		mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), issuerProfile).
			DoAndReturn(func(
				ctx context.Context,
				request *oidc4ci.InitiateIssuanceRequest,
				issuer *profileapi.Issuer,
			) (*oidc4ci.InitiateIssuanceResponse, error) {
				require.Len(t, request.CredentialConfiguration, 1)
				require.EqualValues(t, expectedCred,
					*request.CredentialConfiguration[0].ComposeCredential.Credential)

				return resp, nil
			})
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

		controller := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4CIService: mockOIDC4CISvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.IssuerEventTopic,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		c = echoContext(withRequestBody(req))

		err = controller.InitiateCredentialComposeIssuance(c, profileID, profileVersion)
		require.NoError(t, err)
	})
}

func TestController_InitiateCredentialIssuance(t *testing.T) {
	issuerProfile := &profileapi.Issuer{
		OrganizationID: orgID,
		ID:             profileID,
		Version:        profileVersion,
		Active:         true,
		OIDCConfig:     &profileapi.OIDCConfig{},
		VCConfig: &profileapi.VCConfig{
			Model: vcsverifiable.V2_0,
		},
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				ID: "templateID",
			},
		},
	}

	now := lo.ToPtr(time.Now().UTC())
	req, err := json.Marshal(&InitiateOIDC4CIRequest{
		ClaimEndpoint:             lo.ToPtr("https://vcs.pb.example.com/claim"),
		ClientInitiateIssuanceUrl: lo.ToPtr("https://wallet.example.com/initiate_issuance"),
		ClientWellknown:           lo.ToPtr("https://wallet.example.com/.well-known/openid-configuration"),
		CredentialConfiguration: lo.ToPtr([]InitiateIssuanceCredentialConfiguration{
			{
				ClaimData: lo.ToPtr(map[string]interface{}{
					"key": "value",
				}),
				ClaimEndpoint:         lo.ToPtr("https://vcs.pb.example.com/claim"),
				CredentialTemplateId:  lo.ToPtr("templateID"),
				CredentialExpiresAt:   now,
				CredentialName:        lo.ToPtr("name1"),
				CredentialDescription: lo.ToPtr("description1"),
			},
			{
				ClaimData: lo.ToPtr(map[string]interface{}{
					"key2": "value2",
				}),
				ClaimEndpoint:         lo.ToPtr("https://vcs.pb.example.com/claim2"),
				CredentialDescription: lo.ToPtr("description2"),
				CredentialExpiresAt:   now,
				CredentialName:        lo.ToPtr("name2"),
				CredentialTemplateId:  lo.ToPtr("templateID1"),
				Compose: &DeprecatedComposeOIDC4CICredential{
					Credential:     nil,
					IdTemplate:     lo.ToPtr("something"),
					OverrideIssuer: lo.ToPtr(true),
				},
			},
		}),
		CredentialExpiresAt:     now,
		GrantType:               lo.ToPtr(InitiateOIDC4CIRequestGrantTypeAuthorizationCode),
		OpState:                 lo.ToPtr("eyJhbGciOiJSU0Et"),
		ResponseType:            lo.ToPtr("token"),
		Scope:                   lo.ToPtr([]string{"openid"}),
		UserPinRequired:         lo.ToPtr(true),
		WalletInitiatedIssuance: lo.ToPtr(true),
	})
	require.NoError(t, err)

	resp := &oidc4ci.InitiateIssuanceResponse{
		InitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
		TxID:                "txID",
	}

	var (
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		mockOIDC4CISvc = NewMockOIDC4CIService(gomock.NewController(t))
		mockEventSvc   = NewMockEventService(gomock.NewController(t))
		c              echo.Context
	)

	t.Run("Success", func(t *testing.T) {
		expectedInitiateIssuanceReq := &oidc4ci.InitiateIssuanceRequest{
			ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
			ClientWellKnownURL:        "https://wallet.example.com/.well-known/openid-configuration",
			GrantType:                 "authorization_code",
			ResponseType:              "token",
			Scope:                     []string{"openid"},
			OpState:                   "eyJhbGciOiJSU0Et",
			UserPinRequired:           true,
			WalletInitiatedIssuance:   true,
			CredentialConfiguration: []oidc4ci.InitiateIssuanceCredentialConfiguration{
				{
					ClaimData: map[string]interface{}{
						"key": "value",
					},
					ClaimEndpoint:         "https://vcs.pb.example.com/claim",
					CredentialTemplateID:  "templateID",
					CredentialExpiresAt:   now,
					CredentialName:        "name1",
					CredentialDescription: "description1",
					ComposeCredential:     nil,
				},
				{
					ClaimData: map[string]interface{}{
						"key2": "value2",
					},
					ClaimEndpoint:         "https://vcs.pb.example.com/claim2",
					CredentialTemplateID:  "templateID1",
					CredentialExpiresAt:   now,
					CredentialName:        "name2",
					CredentialDescription: "description2",
					ComposeCredential: &oidc4ci.InitiateIssuanceComposeCredential{
						Credential:     nil,
						IDTemplate:     "something",
						OverrideIssuer: true,
					},
				},
			},
		}

		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
		mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), expectedInitiateIssuanceReq, issuerProfile).
			Times(1).Return(resp, nil)
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(0)

		controller := NewController(&Config{
			ProfileSvc:     mockProfileSvc,
			OIDC4CIService: mockOIDC4CISvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.IssuerEventTopic,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		c = echoContext(withRequestBody(req))

		err = controller.InitiateCredentialIssuance(c, profileID, profileVersion)
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(0)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					c = echoContext(withRequestBody(req), withTenantID(""))
				},
				check: func(t *testing.T, err error) {
					requireAuthError(t, err)
				},
			},
			{
				name: "Invalid profile",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1)
					c = echoContext(withRequestBody(req), withTenantID("invalid"))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile with given id")
				},
			},
			{
				name: "Invalid request body",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1)
					c = echoContext(withRequestBody([]byte(`{{`)))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "invalid character '{' looking for beginning of object key string")
				},
			},
			{
				name: "Profile does not exist in the underlying storage",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(nil, resterr.ErrProfileNotFound)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1)
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(nil, errors.New("get profile error"))
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1).DoAndReturn(
						func(ctx context.Context, topic string, messages ...*spi.Event) error {
							assert.Len(t, messages, 1)

							msg := messages[0]

							assert.Equal(t, msg.Type, spi.IssuerOIDCInteractionFailed)

							ep := &oidc4ci.EventPayload{}

							jsonData, errMarshal := json.Marshal(msg.Data.(map[string]interface{}))
							require.NoError(t, errMarshal)

							assert.NoError(t, json.Unmarshal(jsonData, ep))

							assert.Equal(t, "unauthorized", ep.ErrorCode)
							assert.Equal(t, resterr.IssuerOIDC4ciSvcComponent, resterr.Component(ep.ErrorComponent))

							return nil
						},
					)
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
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(nil, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1).DoAndReturn(
						func(ctx context.Context, topic string, messages ...*spi.Event) error {
							assert.Len(t, messages, 1)

							msg := messages[0]

							assert.Equal(t, msg.Type, spi.IssuerOIDCInteractionFailed)

							ep := &oidc4ci.EventPayload{}

							jsonData, errMarshal := json.Marshal(msg.Data)
							require.NoError(t, errMarshal)

							assert.NoError(t, json.Unmarshal(jsonData, ep))

							assert.Equal(t, "unauthorized", ep.ErrorCode)
							assert.Equal(t, resterr.IssuerOIDC4ciSvcComponent, resterr.Component(ep.ErrorComponent))

							return nil
						},
					)
					c = echoContext(withRequestBody(req))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(), "profile with given id testID_v1.0, doesn't exist")
				},
			},
			{
				name: "Initiate issuance: *oidc4cierr.Error error",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oidc4cierr.NewUnauthorizedError(errors.New("some error"))) //nolint:lll
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1).DoAndReturn(
						func(ctx context.Context, topic string, messages ...*spi.Event) error {
							assert.Len(t, messages, 1)

							msg := messages[0]

							assert.Equal(t, msg.Type, spi.IssuerOIDCInteractionFailed)

							ep := &oidc4ci.EventPayload{}

							jsonData, errMarshal := json.Marshal(msg.Data)
							require.NoError(t, errMarshal)

							assert.NoError(t, json.Unmarshal(jsonData, ep))

							assert.Equal(t, "unauthorized", ep.ErrorCode)
							assert.Equal(t, "unauthorized[http status: 401]: some error", ep.Error)

							return nil
						},
					)

					r, marshalErr := json.Marshal(&InitiateOIDC4CIRequest{})
					require.NoError(t, marshalErr)

					c = echoContext(withRequestBody(r))
				},
				check: func(t *testing.T, err error) {
					require.Error(t, err)
					require.Contains(t, err.Error(),
						"unauthorized[operation: InitiateCredentialIssuance; http status: 401]: some error")
				},
			},
			{
				name: "System error",
				setup: func() {
					mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(issuerProfile, nil)
					mockOIDC4CISvc.EXPECT().InitiateIssuance(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("service error")) //nolint:lll
					mockEventSvc.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).Times(1).DoAndReturn(
						func(ctx context.Context, topic string, messages ...*spi.Event) error {
							assert.Len(t, messages, 1)

							msg := messages[0]

							assert.Equal(t, msg.Type, spi.IssuerOIDCInteractionFailed)

							ep := &oidc4ci.EventPayload{}

							jsonData, errMarshal := json.Marshal(msg.Data)
							require.NoError(t, errMarshal)

							assert.NoError(t, json.Unmarshal(jsonData, ep))

							assert.Equal(t, "bad_request", ep.ErrorCode)
							assert.Equal(t, "service error", ep.Error)

							return nil
						},
					)
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
					Tracer:         nooptracer.NewTracerProvider().Tracer(""),
					EventSvc:       mockEventSvc,
					EventTopic:     spi.IssuerEventTopic,
				})

				err = controller.InitiateCredentialIssuance(c, profileID, profileVersion)
				tt.check(t, err)
			})
		}
	})
}

func TestController_PushAuthorizationDetails(t *testing.T) {
	var (
		mockOIDC4CISvc                  = NewMockOIDC4CIService(gomock.NewController(t))
		req                             string
		authorizationDetailsFormatBased = `[{
    "type": "openid_credential",
    "format": "ldp_vc",
    "credential_definition": {
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "credentialSubject": {
        "given_name": {},
        "family_name": {},
        "degree": {}
      }
    }
  }]`
		authorizationDetailsCredentialConfigurationIDBased = `[{
		 "type": "openid_credential",
		 "credential_configuration_id": "UniversityDegreeCredential"
		}]`
	)

	t.Run("Success: AuthorizationDetails contains Format field", func(t *testing.T) {
		mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(nil)

		controller := NewController(&Config{
			OIDC4CIService: mockOIDC4CISvc,
		})

		req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsFormatBased) //nolint:lll
		c := echoContext(withRequestBody([]byte(req)))

		err := controller.PushAuthorizationDetails(c)
		require.NoError(t, err)
	})

	t.Run("Success: AuthorizationDetails contains CredentialConfigurationID field", func(t *testing.T) {
		mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(nil)

		controller := NewController(&Config{
			OIDC4CIService: mockOIDC4CISvc,
		})

		req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsCredentialConfigurationIDBased) //nolint:lll
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

					req = `{"op_state":"opState","authorization_details":[{"type":"invalid","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}]}` //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "type should be 'openid_credential'")
				},
			},
			{
				name: "Credential type not supported",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						errors.New("credential type not supported"))

					req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsFormatBased) //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "credential type not supported")
				},
			},
			{
				name: "Credential format not supported",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						errors.New("credential format not supported"))

					req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsFormatBased) //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "credential format not supported")
				},
			},
			{
				name: "CredentialConfigurationID not supported",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						errors.New("invalid credential configuration ID"))

					req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsFormatBased) //nolint:lll
				},
				check: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "invalid credential configuration ID")
				},
			},
			{
				name: "Service error",
				setup: func() {
					mockOIDC4CISvc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", gomock.Any()).Return(
						errors.New("service error"))

					req = fmt.Sprintf(`{"op_state":"opState","authorization_details":%s}`, authorizationDetailsFormatBased) //nolint:lll
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
	var (
		authorizationDetailsFormatBased = `{
    "type": "openid_credential",
    "format": "ldp_vc",
    "credential_definition": {
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "credentialSubject": {
        "given_name": {},
        "family_name": {},
        "degree": {}
      }
    }
  }`
		authorizationDetailsCredentialConfigurationIDBased = `{
		 "type": "openid_credential",
		 "credential_configuration_id": "UniversityDegreeCredential"
		}`
	)

	t.Run("Success", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareClaimDataAuthorizationRequest,
			) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error) {
				assert.Equal(t, "123", req.OpState)
				assert.Len(t, req.AuthorizationDetails, 2)

				ad := req.AuthorizationDetails[0]

				assert.Equal(t, ad.Type, "openid_credential")
				assert.Equal(t, ad.Format, vcsverifiable.LdpVC)
				assert.Nil(t, ad.Locations)
				assert.Empty(t, ad.CredentialConfigurationID)
				assert.Nil(t, ad.CredentialDefinition.Context)
				assert.NotNil(t, ad.CredentialDefinition.CredentialSubject)
				assert.Equal(t, ad.CredentialDefinition.Type, []string{"VerifiableCredential", "UniversityDegreeCredential"})
				assert.Equal(t, req.Scope, []string{"scope1", "scope2"})

				ad = req.AuthorizationDetails[1]

				assert.Equal(t, ad.Type, "openid_credential")
				assert.Empty(t, ad.Format)
				assert.Nil(t, ad.Locations)
				assert.Equal(t, ad.CredentialConfigurationID, "UniversityDegreeCredential")
				assert.Nil(t, ad.CredentialDefinition)
				assert.Nil(t, ad.CredentialIdentifiers)

				return &oidc4ci.PrepareClaimDataAuthorizationResponse{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil
			},
		)

		mockProfileService := NewMockProfileService(gomock.NewController(t))
		mockProfileService.EXPECT().GetProfile(profileID, profileVersion).Return(&profileapi.Issuer{
			OIDCConfig: &profileapi.OIDCConfig{},
		}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
			profileSvc:     mockProfileService,
		}

		ad := fmt.Sprintf(`[%s, %s]`, authorizationDetailsFormatBased, authorizationDetailsCredentialConfigurationIDBased)
		req := fmt.Sprintf(
			`{"response_type":"code","op_state":"123","scope":["scope1", "scope2"],"authorization_details":%s}`, ad) //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareAuthorizationRequest(ctx))
	})

	t.Run("Success scope based", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareClaimDataAuthorizationRequest,
			) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error) {
				assert.Equal(t, "123", req.OpState)

				assert.Nil(t, req.AuthorizationDetails)
				assert.Equal(t, req.Scope, []string{"scope1", "scope2"})

				return &oidc4ci.PrepareClaimDataAuthorizationResponse{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil
			},
		)

		mockProfileService := NewMockProfileService(gomock.NewController(t))
		mockProfileService.EXPECT().GetProfile(profileID, profileVersion).Return(&profileapi.Issuer{
			OIDCConfig: &profileapi.OIDCConfig{},
			DataConfig: profileapi.IssuerDataConfig{OIDC4CIAuthStateTTL: 10},
		}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
			profileSvc:     mockProfileService,
		}

		recorder := httptest.NewRecorder()

		req := `{"response_type":"code","op_state":"123","scope":["scope1", "scope2"]}`
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareAuthorizationRequest(ctx))

		var prepareClaimDataAuthorizationResponse PrepareClaimDataAuthorizationResponse

		err := json.NewDecoder(recorder.Body).Decode(&prepareClaimDataAuthorizationResponse)
		assert.NoError(t, err)

		assert.Equal(t, prepareClaimDataAuthorizationResponse.ProfileAuthStateTtl, 10)
	})

	t.Run("read body error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		ctx := echoContext(withRequestBody([]byte(`{{`)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx),
			"invalid character '{' looking for beginning of object key string")
	})

	t.Run("invalid authorization_details.type", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":[{"type":"invalid","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}]}` //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "authorization_details.type")
	})

	t.Run("invalid authorization_details.format", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"response_type":"code","op_state":"123","authorization_details":[{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"invalid","locations":[]}]}` //nolint:lll
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

		ctx := echoContext(withRequestBody([]byte(`{"response_type":"code","op_state":"123"}`)))
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

				return &oidc4ci.PrepareClaimDataAuthorizationResponse{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil
			},
		)

		mockProfileService := NewMockProfileService(gomock.NewController(t))
		mockProfileService.EXPECT().GetProfile(profileID, profileVersion).Return(nil, errors.New("get profile error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
			profileSvc:     mockProfileService,
		}

		ctx := echoContext(withRequestBody([]byte(`{"response_type":"code","op_state":"123"}`)))
		assert.ErrorContains(t, c.PrepareAuthorizationRequest(ctx), "get profile error")
	})
}

func TestController_StoreAuthorizationCodeRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().StoreAuthorizationCode(gomock.Any(), opState, code, nil).Return(
			issuecredential.TxID("1234"), nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := fmt.Sprintf(`{"op_state":"%s","code":"%s"}`, opState, code) //nolint:lll
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.StoreAuthorizationCodeRequest(ctx))
	})

	t.Run("success with flow data", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().StoreAuthorizationCode(gomock.Any(), opState, code,
			&common.WalletInitiatedFlowData{
				ProfileId:      "123",
				ProfileVersion: "xxx",
			}).
			Return(issuecredential.TxID("1234"), nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := fmt.Sprintf(`{"op_state":"%s","code":"%s", "wallet_initiated_flow" : {"profile_id" : "123", "profile_version": "xxx"}}`, opState, code) //nolint:lll
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
	t.Run("success with CredentialDefinition", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState, "", "", "").
			Return(&oidc4ci.ExchangeAuthorizationCodeResult{
				TxID: "TxID",
				AuthorizationDetails: []*issuecredential.AuthorizationDetails{
					getTestAuthorizationDetails(t, true),
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		recorder := httptest.NewRecorder()

		req := fmt.Sprintf(`{"op_state":"%s"}`, opState)
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))
		assert.NoError(t, c.ExchangeAuthorizationCodeRequest(ctx))

		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var exchangeResult ExchangeAuthorizationCodeResponse

		err := json.NewDecoder(recorder.Body).Decode(&exchangeResult)
		assert.NoError(t, err)

		assert.Equal(t, "TxID", exchangeResult.TxId)

		assert.NotNil(t, exchangeResult.AuthorizationDetails)

		checkTestAuthorizationDetailsDTO(t, exchangeResult.AuthorizationDetails, true)
	})
	t.Run("success without CredentialDefinition", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState, "", "", "").
			Return(&oidc4ci.ExchangeAuthorizationCodeResult{
				TxID: "TxID",
				AuthorizationDetails: []*issuecredential.AuthorizationDetails{
					getTestAuthorizationDetails(t, false),
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		recorder := httptest.NewRecorder()

		req := fmt.Sprintf(`{"op_state":"%s"}`, opState)
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))
		assert.NoError(t, c.ExchangeAuthorizationCodeRequest(ctx))

		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var exchangeResult ExchangeAuthorizationCodeResponse

		err := json.NewDecoder(recorder.Body).Decode(&exchangeResult)
		assert.NoError(t, err)

		assert.Equal(t, "TxID", exchangeResult.TxId)

		assert.NotNil(t, exchangeResult.AuthorizationDetails)

		checkTestAuthorizationDetailsDTO(t, exchangeResult.AuthorizationDetails, false)
	})

	t.Run("success without AuthorizationDetails", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState, "", "", "").
			Return(&oidc4ci.ExchangeAuthorizationCodeResult{
				TxID:                 "TxID",
				AuthorizationDetails: nil,
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		recorder := httptest.NewRecorder()

		req := fmt.Sprintf(`{"op_state":"%s"}`, opState)
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))
		assert.NoError(t, c.ExchangeAuthorizationCodeRequest(ctx))

		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var exchangeResult ExchangeAuthorizationCodeResponse

		err := json.NewDecoder(recorder.Body).Decode(&exchangeResult)
		assert.NoError(t, err)

		assert.Equal(t, "TxID", exchangeResult.TxId)

		assert.Nil(t, exchangeResult.AuthorizationDetails)
	})

	t.Run("error from service", func(t *testing.T) {
		opState := uuid.NewString()
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ExchangeAuthorizationCode(gomock.Any(), opState, "", "", "").
			Return(nil, errors.New("unexpected error"))

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
	t.Run("success with pin and authorizationDetails", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "5432", "123", "", "").
			Return(&issuecredential.Transaction{
				ID: "txID",
				TransactionData: issuecredential.TransactionData{
					OpState: "random_op_state",
					Scope:   []string{"a", "b"},
					CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
						{
							AuthorizationDetails:      getTestAuthorizationDetails(t, true),
							CredentialConfigurationID: "CredentialConfigurationID",
						},
					},
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		recorder := httptest.NewRecorder()

		req := `{"pre-authorized_code":"1234", "user_pin" : "5432", "client_id": "123" }` //nolint:lll
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))

		err := c.ValidatePreAuthorizedCodeRequest(ctx)
		assert.NoError(t, err)

		var response ValidatePreAuthorizedCodeResponse
		err = json.NewDecoder(recorder.Body).Decode(&response)
		assert.NoError(t, err)

		assert.Equal(t, "txID", response.TxId)
		assert.Equal(t, "random_op_state", response.OpState)
		assert.Equal(t, []string{"a", "b"}, response.Scopes)

		checkTestAuthorizationDetailsDTO(t, response.AuthorizationDetails, true)
	})

	t.Run("success without pin and without authorizationDetails", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "", "123", "", "").
			Return(&issuecredential.Transaction{
				ID: "txID",
				TransactionData: issuecredential.TransactionData{
					OpState: "random_op_state",
					Scope:   []string{"a", "b"},
					//AuthorizationDetails: nil,
				},
			}, nil)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		recorder := httptest.NewRecorder()

		req := `{"pre-authorized_code":"1234", "client_id": "123" }` //nolint:lll
		ctx := echoContext(withRecorder(recorder), withRequestBody([]byte(req)))
		assert.NoError(t, c.ValidatePreAuthorizedCodeRequest(ctx))

		var response ValidatePreAuthorizedCodeResponse
		err := json.NewDecoder(recorder.Body).Decode(&response)
		assert.NoError(t, err)

		assert.Equal(t, "txID", response.TxId)
		assert.Equal(t, "random_op_state", response.OpState)
		assert.Equal(t, []string{"a", "b"}, response.Scopes)
		assert.Nil(t, response.AuthorizationDetails)
	})

	t.Run("fail with pin", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "1234", "5432", "123", "", "").
			Return(nil, errors.New("unexpected error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"pre-authorized_code":"1234", "user_pin" : "5432", "client_id": "123" }` //nolint:lll
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

// nolint:lll
func TestController_PrepareCredential(t *testing.T) {
	var universityDegreeSchemaDoc map[string]interface{}
	require.NoError(t, json.Unmarshal(universityDegreeSchema, &universityDegreeSchemaDoc))

	sampleVC, err := verifiable.ParseCredential(
		sampleVCUniversityDegree,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)
				assert.Len(t, req.CredentialRequests, 1)
				assert.Empty(t, req.HashedToken)
				assert.Equal(t, []string{"UniversityDegreeCredential"}, req.CredentialRequests[0].CredentialTypes)
				assert.Equal(t, vcsverifiable.OIDCFormat("ldp_vc"), req.CredentialRequests[0].CredentialFormat)
				assert.Empty(t, req.CredentialRequests[0].AudienceClaim)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareCredential(ctx))
	})

	t.Run("success with requested credential response encryption", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{
					CredentialResponseAlgValuesSupported: []string{"ECDH-ES"},
					CredentialResponseEncValuesSupported: []string{"A128CBC-HS256"},
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc","requested_credential_response_encryption":{"alg":"ECDH-ES","enc":"A128CBC-HS256"}}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareCredential(ctx))
	})

	t.Run("invalid body", func(t *testing.T) {
		c := NewController(&Config{})

		req := `{`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "unexpected EOF")
	})

	t.Run("fail to access profile", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Return(nil, errors.New("get profile error"))

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							Retry:      false,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:          mockProfileSvc,
			OIDC4CIService:      mockOIDC4CIService,
			DocumentLoader:      testutil.DocumentLoader(t),
			JSONSchemaValidator: mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "profile")
	})

	t.Run("empty credentials list", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials:    []*oidc4ci.PrepareCredentialResultData{},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:          mockProfileSvc,
			OIDC4CIService:      mockOIDC4CIService,
			DocumentLoader:      testutil.DocumentLoader(t),
			JSONSchemaValidator: mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "empty credentials list")
	})

	t.Run("fail to sign credential", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				Version:        profileVersion,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: nil,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							Retry:      false,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			OIDC4CIService:         mockOIDC4CIService,
			IssueCredentialService: mockIssueCredentialSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "credential")
	})

	t.Run("invalid credential format", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"invalid"}`
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

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "invalid_credential_request")
	})

	t.Run("service oidc4cierr.Error error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(
			nil, oidc4cierr.NewUnauthorizedError(errors.New("some error")))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "unauthorized")
	})

	t.Run("claims JSON schema validation error", func(t *testing.T) {
		invalidVC, err := verifiable.ParseCredential(
			sampleVCInvalidUniversityDegree,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		)
		require.NoError(t, err)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: invalidVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: false,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("validation error"))

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))

		err = c.PrepareCredential(ctx)
		assert.ErrorContains(t, err, "invalid_credential_request[component: issuer.oidc4ci-service; operation: PrepareCredential; "+
			"http status: 400]: validate claims: validation error")
	})

	t.Run("claims JSONLD schema validation error", func(t *testing.T) {
		invalidVC, err := verifiable.ParseCredential(
			sampleInvalidVCJsonLDV2,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		)
		require.NoError(t, err)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Model:  vcsverifiable.V2_0,
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: invalidVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    NewMockJSONSchemaValidator(gomock.NewController(t)),
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))

		err = c.PrepareCredential(ctx)
		require.ErrorContains(t, err, "invalid_credential_request")
	})

	t.Run("credential response encryption is required error", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{
					CredentialResponseEncryptionRequired: true,
					CredentialResponseAlgValuesSupported: []string{"ECDH-ES"},
					CredentialResponseEncValuesSupported: []string{"A128CBC-HS256"},
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "credential response encryption is required")
	})

	t.Run("alg not supported error", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{
					CredentialResponseAlgValuesSupported: []string{"ECDH-ES"},
					CredentialResponseEncValuesSupported: []string{"A128CBC-HS256"},
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc","requested_credential_response_encryption":{"alg":"RSA-OAEP-256","enc":"A128CBC-HS256"}}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "alg RSA-OAEP-256 not supported")
	})

	t.Run("enc not supported error", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{
					CredentialResponseAlgValuesSupported: []string{"ECDH-ES"},
					CredentialResponseEncValuesSupported: []string{"A128CBC-HS256"},
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc","requested_credential_response_encryption":{"alg":"ECDH-ES","enc":"A192CBC-HS384"}}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareCredential(ctx), "enc A192CBC-HS384 not supported")
	})

	t.Run("invalid context for model", func(t *testing.T) {
		sampleVC, err := verifiable.ParseCredential(
			sampleVCUniversityDegree,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		)
		require.NoError(t, err)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		issuerProfile := &profileapi.Issuer{
			OrganizationID: orgID,
			ID:             profileID,
			VCConfig: &profileapi.VCConfig{
				Format: vcsverifiable.Ldp,
			},
		}

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(issuerProfile, nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: NewMockIssueCredentialService(gomock.NewController(t)),
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    NewMockJSONSchemaValidator(gomock.NewController(t)),
		})

		t.Run("Model w3c-vc-2.0", func(t *testing.T) {
			issuerProfile.VCConfig.Model = vcsverifiable.V2_0

			req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
			ctx := echoContext(withRequestBody([]byte(req)))

			err = c.PrepareCredential(ctx)
			require.ErrorContains(t, err, "invalid context for model w3c-vc-2.0")
		})

		t.Run("Unsupported model", func(t *testing.T) {
			issuerProfile.VCConfig.Model = "v1.3"

			req := `{"tx_id":"123","types":["UniversityDegreeCredential"],"format":"ldp_vc"}`
			ctx := echoContext(withRequestBody([]byte(req)))

			err = c.PrepareCredential(ctx)
			require.ErrorContains(t, err, "unsupported VC model: v1.3")
		})
	})
}

// nolint:lll
func TestController_PrepareBatchCredential(t *testing.T) {
	var universityDegreeSchemaDoc map[string]interface{}
	require.NoError(t, json.Unmarshal(universityDegreeSchema, &universityDegreeSchemaDoc))

	sampleVC, err := verifiable.ParseCredential(
		sampleVCUniversityDegree,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
				OIDCConfig: &profileapi.OIDCConfig{
					CredentialResponseAlgValuesSupported: []string{"ECDH-ES"},
					CredentialResponseEncValuesSupported: []string{"A128CBC-HS256"},
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return(nil, nil)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)
				assert.Len(t, req.CredentialRequests, 2)
				assert.Empty(t, req.HashedToken)
				assert.Equal(t, []string{"UniversityDegreeCredential"}, req.CredentialRequests[0].CredentialTypes)
				assert.Equal(t, vcsverifiable.OIDCFormat("ldp_vc"), req.CredentialRequests[0].CredentialFormat)
				assert.Empty(t, req.CredentialRequests[0].AudienceClaim)

				assert.Equal(t, []string{"PermanentResidentCard"}, req.CredentialRequests[1].CredentialTypes)
				assert.Equal(t, vcsverifiable.OIDCFormat("jwt_vc_json"), req.CredentialRequests[1].CredentialFormat)
				assert.Empty(t, req.CredentialRequests[0].AudienceClaim)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					NotificationID: "",
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							CredentialTemplate: &profileapi.CredentialTemplate{
								JSONSchema:   string(universityDegreeSchema),
								JSONSchemaID: "https://trustbloc.com/universitydegree.schema.json",
								Checks: profileapi.CredentialTemplateChecks{
									Strict: true,
								},
							},
							Retry:                   false,
							EnforceStrictValidation: true,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))
		mockJSONSchemaValidator.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return(nil)

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			IssueCredentialService: mockIssueCredentialSvc,
			OIDC4CIService:         mockOIDC4CIService,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		vc1 := `{"types":["UniversityDegreeCredential"],"format":"ldp_vc","requested_credential_response_encryption":{"alg":"ECDH-ES","enc":"A128CBC-HS256"}}`
		vc2 := `{"types":["PermanentResidentCard"],"format":"jwt_vc_json","requested_credential_response_encryption":{"alg":"ECDH-ES","enc":"A128CBC-HS256"}}`
		req := fmt.Sprintf(`{"tx_id":"123","credential_requests":[%s,%s]}`, vc1, vc2)
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.NoError(t, c.PrepareBatchCredential(ctx))
	})

	t.Run("invalid body", func(t *testing.T) {
		c := NewController(&Config{})

		req := `{`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "unexpected EOF")
	})

	t.Run("fail to access profile", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Return(nil, errors.New("get profile error"))

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: sampleVC,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							Retry:      false,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:          mockProfileSvc,
			OIDC4CIService:      mockOIDC4CIService,
			DocumentLoader:      testutil.DocumentLoader(t),
			JSONSchemaValidator: mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"ldp_vc"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "profile")
	})

	t.Run("empty credentials list", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials:    []*oidc4ci.PrepareCredentialResultData{},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:          mockProfileSvc,
			OIDC4CIService:      mockOIDC4CIService,
			DocumentLoader:      testutil.DocumentLoader(t),
			JSONSchemaValidator: mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"ldp_vc"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "empty credentials list")
	})

	t.Run("fail to sign credential", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(
			&profileapi.Issuer{
				OrganizationID: orgID,
				ID:             profileID,
				Version:        profileVersion,
				VCConfig: &profileapi.VCConfig{
					Format: vcsverifiable.Ldp,
				},
			}, nil)

		mockIssueCredentialSvc := NewMockIssueCredentialService(gomock.NewController(t))
		mockIssueCredentialSvc.EXPECT().IssueCredential(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).DoAndReturn(
			func(
				ctx context.Context,
				req *oidc4ci.PrepareCredential,
			) (*oidc4ci.PrepareCredentialResult, error) {
				assert.Equal(t, issuecredential.TxID("123"), req.TxID)

				return &oidc4ci.PrepareCredentialResult{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
					Credentials: []*oidc4ci.PrepareCredentialResultData{
						{
							Credential: nil,
							Format:     vcsverifiable.Ldp,
							OidcFormat: "",
							Retry:      false,
						},
					},
				}, nil
			},
		)

		mockJSONSchemaValidator := NewMockJSONSchemaValidator(gomock.NewController(t))

		c := NewController(&Config{
			ProfileSvc:             mockProfileSvc,
			OIDC4CIService:         mockOIDC4CIService,
			IssueCredentialService: mockIssueCredentialSvc,
			DocumentLoader:         testutil.DocumentLoader(t),
			JSONSchemaValidator:    mockJSONSchemaValidator,
		})

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"ldp_vc"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "credential")
	})

	t.Run("invalid credential format", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"invalid"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "format")
	})

	t.Run("service error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(
			nil, errors.New("service error"))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"ldp_vc"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "service error")
	})

	t.Run("service oidc4cierr.Error error", func(t *testing.T) {
		mockOIDC4CIService := NewMockOIDC4CIService(gomock.NewController(t))
		mockOIDC4CIService.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(
			nil, oidc4cierr.NewUnauthorizedError(errors.New("invalid_credential_request")))

		c := &Controller{
			oidc4ciService: mockOIDC4CIService,
		}

		req := `{"tx_id":"123","credential_requests":[{"types":["UniversityDegreeCredential"],"format":"ldp_vc"}]}`
		ctx := echoContext(withRequestBody([]byte(req)))
		assert.ErrorContains(t, c.PrepareBatchCredential(ctx), "unauthorized")
	})
}

func TestOpenIdCredentialIssuerConfiguration(t *testing.T) {
	type handler func(ctx echo.Context, profileID, profileVersion string) error

	host := "https://localhost"

	profile := &profileapi.Issuer{
		Name: "random_name",
		URL:  "https://localhost.com.local/abcd",
		VCConfig: &profileapi.VCConfig{
			DIDMethod: "orb",
			KeyType:   "ECDSASecp256k1DER",
		},
		CredentialMetaData: &profileapi.CredentialMetaData{
			CredentialsConfigurationSupported: map[string]*profileapi.CredentialsConfigurationSupported{},
		},
	}

	t.Run("Success JWT", func(t *testing.T) {
		openidIssuerConfigProvider := NewMockOpenIDCredentialIssuerConfigProvider(gomock.NewController(t))
		openidIssuerConfigProvider.EXPECT().GetOpenIDCredentialIssuerConfig(profile).Return(nil, "aa.bb.cc", nil).Times(2)

		profileSvc := NewMockProfileService(gomock.NewController(t))
		profileSvc.EXPECT().GetProfile(profileID, profileVersion).Return(profile, nil).Times(2)

		c := &Controller{
			externalHostURL:            host,
			profileSvc:                 profileSvc,
			openidIssuerConfigProvider: openidIssuerConfigProvider,
		}

		handlers := []handler{
			c.OpenidCredentialIssuerConfig,
			c.OpenidCredentialIssuerConfigV2,
		}

		for _, handlerMethod := range handlers {
			recorder := httptest.NewRecorder()

			echoCtx := echoContext(withRecorder(recorder))

			err := handlerMethod(echoCtx, profileID, profileVersion)
			assert.NoError(t, err)

			bodyBytes, err := io.ReadAll(recorder.Body)
			assert.NoError(t, err)

			assert.Equal(t, `{"signed_metadata":"aa.bb.cc"}`, string(bodyBytes))
			assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		}
	})

	t.Run("Success JSON", func(t *testing.T) {
		openidIssuerConfigProvider := NewMockOpenIDCredentialIssuerConfigProvider(gomock.NewController(t))
		openidIssuerConfigProvider.EXPECT().GetOpenIDCredentialIssuerConfig(profile).Return(
			&WellKnownOpenIDIssuerConfiguration{
				CredentialIssuer: lo.ToPtr("https://example.com"),
			}, "", nil).Times(2)

		profileSvc := NewMockProfileService(gomock.NewController(t))
		profileSvc.EXPECT().GetProfile(profileID, profileVersion).Return(profile, nil).Times(2)

		c := &Controller{
			externalHostURL:            host,
			profileSvc:                 profileSvc,
			openidIssuerConfigProvider: openidIssuerConfigProvider,
		}

		handlers := []handler{
			c.OpenidCredentialIssuerConfig,
			c.OpenidCredentialIssuerConfigV2,
		}

		for _, handlerMethod := range handlers {
			recorder := httptest.NewRecorder()

			echoCtx := echoContext(withRecorder(recorder))

			err := handlerMethod(echoCtx, profileID, profileVersion)
			assert.NoError(t, err)

			bodyBytes, err := io.ReadAll(recorder.Body)
			assert.NoError(t, err)

			assert.Contains(t, string(bodyBytes), "\"credential_issuer\":\"https://example.com\"")
			assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		}
	})

	t.Run("profile error", func(t *testing.T) {
		svc := NewMockProfileService(gomock.NewController(t))
		svc.EXPECT().GetProfile(profileID, profileVersion).
			Return(nil, errors.New("unexpected error")).Times(2)

		c := &Controller{
			externalHostURL: host + "/",
			profileSvc:      svc,
		}

		handlers := []handler{
			c.OpenidCredentialIssuerConfig,
			c.OpenidCredentialIssuerConfigV2,
		}

		for _, handlerMethod := range handlers {
			recorder := httptest.NewRecorder()

			echoCtx := echoContext(withRecorder(recorder))

			err := handlerMethod(echoCtx, profileID, profileVersion)
			assert.Error(t, err)
		}
	})
}

func TestCredentialIssuanceHistory(t *testing.T) {
	credentialIssuanceStore := NewMockCredentialIssuanceHistoryStore(gomock.NewController(t))

	t.Run("Success", func(t *testing.T) {
		txID := lo.ToPtr(uuid.NewString())
		iss := timeutil.NewTime(time.Now())
		credID := lo.ToPtr(uuid.NewString())

		credentialMetadata := &credentialstatus.CredentialMetadata{
			CredentialID:   "credentialID",
			Issuer:         "testIssuer",
			ProfileVersion: profileVersion,
			CredentialType: []string{"verifiableCredential"},
			TransactionID:  *txID,
			IssuanceDate:   iss,
			ExpirationDate: nil,
		}

		credentialIssuanceStore.EXPECT().
			GetIssuedCredentialsMetadata(gomock.Any(), profileID, txID, credID).
			Times(1).
			Return([]*credentialstatus.CredentialMetadata{credentialMetadata}, nil)

		c := &Controller{
			credentialIssuanceHistoryStore: credentialIssuanceStore,
		}

		recorder := httptest.NewRecorder()

		echoCtx := echoContext(withRecorder(recorder))

		err := c.CredentialIssuanceHistory(echoCtx, profileID, CredentialIssuanceHistoryParams{
			TxID:         txID,
			CredentialID: credID,
		})
		assert.NoError(t, err)

		var gotResponse []CredentialIssuanceHistoryData
		err = json.NewDecoder(recorder.Body).Decode(&gotResponse)
		assert.NoError(t, err)

		expectedResponse := []CredentialIssuanceHistoryData{
			{
				CredentialId:    "credentialID",
				CredentialTypes: []string{"verifiableCredential"},
				ExpirationDate:  nil,
				IssuanceDate:    lo.ToPtr(iss.Time.Format(time.RFC3339)),
				Issuer:          "testIssuer",
				TransactionId:   txID,
				ProfileVersion:  lo.ToPtr(profileVersion),
			},
		}

		assert.Equal(t, expectedResponse, gotResponse)
	})

	t.Run("credentialIssuanceHistoryStore error", func(t *testing.T) {
		credentialIssuanceStore.EXPECT().
			GetIssuedCredentialsMetadata(gomock.Any(), profileID, nil, nil).
			Times(1).
			Return(nil, errors.New("some error"))

		c := &Controller{
			credentialIssuanceHistoryStore: credentialIssuanceStore,
		}

		recorder := httptest.NewRecorder()

		echoCtx := echoContext(withRecorder(recorder))

		err := c.CredentialIssuanceHistory(echoCtx, profileID, CredentialIssuanceHistoryParams{})
		assert.Error(t, err)
	})
}

func TestSetCredentialRefreshState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		profileRepo := NewMockProfileService(gomock.NewController(t))
		credRefreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		c := &Controller{
			profileSvc:               profileRepo,
			credentialRefreshService: credRefreshSvc,
		}

		recorder := httptest.NewRecorder()

		reqBody := &SetCredentialRefreshStateRequest{
			Claims: map[string]interface{}{
				"claim1": "value1",
			},
			CredentialDescription: lo.ToPtr("some-cred-desc"),
			CredentialId:          "some-cred-id",
			CredentialName:        lo.ToPtr("some-cred-name"),
		}
		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		echoCtx := echoContext(
			withRecorder(recorder),
			withRequestBody(data),
		)

		issuer := profileapi.Issuer{
			ID: "abc",
		}
		profileRepo.EXPECT().GetProfile(profileID, profileVersion).
			Return(&issuer, nil)

		credRefreshSvc.EXPECT().CreateRefreshState(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, request *refresh.CreateRefreshStateRequest) (string, error) {
				assert.EqualValues(t, reqBody.CredentialId, request.CredentialID)
				assert.EqualValues(t, reqBody.CredentialName, request.CredentialName)
				assert.EqualValues(t, reqBody.CredentialDescription, request.CredentialDescription)
				assert.EqualValues(t, reqBody.Claims, request.Claims)
				assert.EqualValues(t, issuer, request.Issuer)

				return "some-value", nil
			})

		err = c.SetCredentialRefreshState(echoCtx, profileID, profileVersion)
		assert.NoError(t, err)
	})

	t.Run("invalid body", func(t *testing.T) {
		profileRepo := NewMockProfileService(gomock.NewController(t))
		credRefreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		c := &Controller{
			profileSvc:               profileRepo,
			credentialRefreshService: credRefreshSvc,
		}

		recorder := httptest.NewRecorder()

		echoCtx := echoContext(
			withRecorder(recorder),
			withRequestBody([]byte("{")),
		)

		err := c.SetCredentialRefreshState(echoCtx, profileID, profileVersion)
		assert.Error(t, err)
	})

	t.Run("profile not found", func(t *testing.T) {
		profileRepo := NewMockProfileService(gomock.NewController(t))
		credRefreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		c := &Controller{
			profileSvc:               profileRepo,
			credentialRefreshService: credRefreshSvc,
		}

		recorder := httptest.NewRecorder()

		reqBody := &SetCredentialRefreshStateRequest{
			Claims: map[string]interface{}{
				"claim1": "value1",
			},
			CredentialDescription: lo.ToPtr("some-cred-desc"),
			CredentialId:          "some-cred-id",
			CredentialName:        lo.ToPtr("some-cred-name"),
		}
		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		echoCtx := echoContext(
			withRecorder(recorder),
			withRequestBody(data),
		)

		profileRepo.EXPECT().GetProfile(profileID, profileVersion).
			Return(nil, errors.New("profile not found"))

		err = c.SetCredentialRefreshState(echoCtx, profileID, profileVersion)
		assert.ErrorContains(t, err, "profile not found")
	})

	t.Run("service err", func(t *testing.T) {
		profileRepo := NewMockProfileService(gomock.NewController(t))
		credRefreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		c := &Controller{
			profileSvc:               profileRepo,
			credentialRefreshService: credRefreshSvc,
		}

		recorder := httptest.NewRecorder()

		reqBody := &SetCredentialRefreshStateRequest{
			Claims: map[string]interface{}{
				"claim1": "value1",
			},
			CredentialDescription: lo.ToPtr("some-cred-desc"),
			CredentialId:          "some-cred-id",
			CredentialName:        lo.ToPtr("some-cred-name"),
		}
		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		echoCtx := echoContext(
			withRecorder(recorder),
			withRequestBody(data),
		)

		issuer := profileapi.Issuer{
			ID: "abc",
		}
		profileRepo.EXPECT().GetProfile(profileID, profileVersion).
			Return(&issuer, nil)

		credRefreshSvc.EXPECT().CreateRefreshState(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, request *refresh.CreateRefreshStateRequest) (string, error) {
				return "", errors.New("invalid request")
			})

		err = c.SetCredentialRefreshState(echoCtx, profileID, profileVersion)
		assert.ErrorContains(t, err, "invalid request")
	})
}

func Test_getCredentialSubjects(t *testing.T) {
	t.Run("subject", func(t *testing.T) {
		subjects, err := getCredentialSubjects(verifiable.Subject{ID: "id1"})
		require.NoError(t, err)
		require.Len(t, subjects, 1)
	})

	t.Run("slice of subjects", func(t *testing.T) {
		subjects, err := getCredentialSubjects([]verifiable.Subject{{ID: "id1"}, {ID: "id2"}})
		require.NoError(t, err)
		require.Len(t, subjects, 2)
	})

	t.Run("invalid subject", func(t *testing.T) {
		subjects, err := getCredentialSubjects("id2")
		require.EqualError(t, err, "invalid type for credential subject: string")
		require.Len(t, subjects, 0)
	})

	t.Run("nil subject", func(t *testing.T) {
		subjects, err := getCredentialSubjects(nil)
		require.NoError(t, err)
		require.Len(t, subjects, 0)
	})
}

func Test_sendFailedEvent(t *testing.T) {
	t.Run("marshal error", func(t *testing.T) {
		c := NewController(&Config{})

		c.marshal = func(any) ([]byte, error) {
			return nil, errors.New("injected marshal error")
		}

		require.NotPanics(t, func() {
			c.sendFailedEvent(context.Background(), "", "", "", "", "", "")
		})
	})

	t.Run("publish error", func(t *testing.T) {
		evtSvc := NewMockEventService(gomock.NewController(t))
		evtSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("publish error"))

		c := NewController(&Config{EventSvc: evtSvc})

		require.NotPanics(t, func() {
			c.sendFailedEvent(context.Background(), "", "", "", "", "", "")
		})
	})
}

func TestValidateRawCredential(t *testing.T) {
	c := &Controller{}

	t.Run("validate credentialSubjectType", func(t *testing.T) {
		assert.ErrorContains(t, c.ValidateRawCredential(map[string]any{
			"@context": []any{
				"https://www.w3.org/ns/credentials/v2",
			},
			"credentialSubject": 1234,
		}, &profileapi.Issuer{}), "credential_subject must be an object or an array of objects")
	})

	t.Run("validate credentialSubject exists", func(t *testing.T) {
		assert.ErrorContains(t, c.ValidateRawCredential(map[string]any{
			"@context": []any{
				"https://www.w3.org/ns/credentials/v2",
			},
		}, &profileapi.Issuer{}), "credential_subject must be specified")
	})

	t.Run("validate credentialSubject properties", func(t *testing.T) {
		assert.ErrorContains(t, c.ValidateRawCredential(map[string]any{
			"@context": []interface{}{
				"https://www.w3.org/ns/credentials/v2",
			},
			"credentialSubject": []any{
				map[string]any{},
			},
		}, &profileapi.Issuer{}), "each credential_subject must have properties")
	})

	t.Run("validate credentialSubject at least one subject", func(t *testing.T) {
		assert.ErrorContains(t, c.ValidateRawCredential(map[string]any{
			"@context": []interface{}{
				"https://www.w3.org/ns/credentials/v2",
			},
			"credentialSubject": []any{},
		}, &profileapi.Issuer{}), "must have at least one subject")
	})
}

func TestValidateRelatedResources(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Controller{}

		assert.NoError(t, c.ValidateRelatedResources([]any{
			map[string]any{
				"id":        "https://example.com/credential",
				"digestSRI": "sha256-1234",
			},
			map[string]any{
				"id":        "https://example.com/credential1",
				"digestSRI": "xxx",
			},
		}))
	})

	t.Run("duplicate", func(t *testing.T) {
		c := &Controller{}

		assert.ErrorContains(t, c.ValidateRelatedResources([]any{
			map[string]any{
				"id":        "https://example.com/credential",
				"digestSRI": "sha256-1234",
			},
			map[string]any{
				"id":        "https://example.com/credential",
				"digestSRI": "xxx",
			},
		}), "relatedResource must have unique ids")
	})

	t.Run("duplicate", func(t *testing.T) {
		c := &Controller{}

		assert.ErrorContains(t, c.ValidateRelatedResources([]any{
			map[string]any{
				"id": "https://example.com/credential",
			},
		}), "digestMultibase or digestSRI")
	})

	t.Run("wrong type", func(t *testing.T) {
		c := &Controller{}

		assert.ErrorContains(t, c.ValidateRelatedResources(1234),
			"relatedResource must be an array")
	})

	t.Run("no records", func(t *testing.T) {
		c := &Controller{}

		assert.NoError(t, c.ValidateRelatedResources(nil))
	})
}

type options struct {
	tenantID         string
	oAuthClientRoles string
	requestBody      []byte
	responseWriter   http.ResponseWriter
}

type contextOpt func(*options)

func withTenantID(tenantID string) contextOpt {
	return func(o *options) {
		o.tenantID = tenantID
	}
}

func withRequestBody(body []byte) contextOpt {
	return func(o *options) {
		o.requestBody = body
	}
}

func withOAuthClientRoles(roles string) contextOpt {
	return func(o *options) {
		o.oAuthClientRoles = roles
	}
}

func withRecorder(w http.ResponseWriter) contextOpt {
	return func(o *options) {
		o.responseWriter = w
	}
}

func echoContext(opts ...contextOpt) echo.Context {
	o := &options{
		tenantID:       orgID,
		responseWriter: httptest.NewRecorder(),
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

	if o.tenantID != "" {
		req.Header.Set("X-Tenant-ID", o.tenantID)
	}

	if o.oAuthClientRoles != "" {
		req.Header.Set("X-Client-Roles", o.oAuthClientRoles)
	}

	return e.NewContext(req, o.responseWriter)
}

func requireValidationError(t *testing.T, expectedCode string, incorrectValueName string, component resterr.Component, actual error) {
	var actualErr *oidc4cierr.Error
	require.ErrorAs(t, actual, &actualErr)

	require.Equal(t, expectedCode, string(actualErr.ErrorCode))
	require.Equal(t, incorrectValueName, actualErr.IncorrectValue)
	require.Equal(t, actualErr.Component(), string(component))
	require.Error(t, actualErr.Err)
}

func requireAuthError(t *testing.T, actual error) {
	var actualErr *oidc4cierr.Error
	require.ErrorAs(t, actual, &actualErr)

	require.Equal(t, "unauthorized", string(actualErr.ErrorCode))
}

func getTestAuthorizationDetails(t *testing.T, includeCredentialDefinition bool) *issuecredential.AuthorizationDetails {
	t.Helper()

	res := &issuecredential.AuthorizationDetails{
		CredentialConfigurationID: "CredentialConfigurationID",
		Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
		Type:                      "openid_credential",
		CredentialDefinition:      nil,
		Format:                    "jwt",
		CredentialIdentifiers:     []string{"CredentialIdentifiers1", "CredentialIdentifiers2"},
	}

	if includeCredentialDefinition {
		res.CredentialDefinition = &issuecredential.CredentialDefinition{
			Context:           []string{"https://example.com/context/1", "https://example.com/context/2"},
			CredentialSubject: map[string]interface{}{"key": "value"},
			Type:              []string{"VerifiableCredential", "UniversityDegreeCredential"},
		}
	}

	return res
}

func checkTestAuthorizationDetailsDTO(
	t *testing.T,
	authorizationDetailsDTOList *[]common.AuthorizationDetails,
	includeCredentialDefinition bool,
) {
	authorizationDetailsReceived := *authorizationDetailsDTOList

	assert.Len(t, authorizationDetailsReceived, 1)
	assert.Equal(t, "CredentialConfigurationID", *authorizationDetailsReceived[0].CredentialConfigurationId)
	assert.Equal(t, []string{"CredentialIdentifiers1", "CredentialIdentifiers2"},
		*authorizationDetailsReceived[0].CredentialIdentifiers)
	assert.Equal(t, "jwt", lo.FromPtr(authorizationDetailsReceived[0].Format))
	assert.Equal(t, []string{"https://example.com/rs1", "https://example.com/rs2"},
		*authorizationDetailsReceived[0].Locations)
	assert.Equal(t, "openid_credential", authorizationDetailsReceived[0].Type)

	ad := authorizationDetailsReceived[0].CredentialDefinition

	if includeCredentialDefinition {
		assert.NotNil(t, ad)
		assert.Equal(t, []string{"https://example.com/context/1", "https://example.com/context/2"}, *ad.Context)
		assert.Equal(t, map[string]interface{}{"key": "value"}, *ad.CredentialSubject)
		assert.Equal(t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, ad.Type)
	} else {
		assert.Nil(t, ad)
	}
}
