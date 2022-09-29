/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"

	"github.com/golang/mock/gomock"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

const (
	orgID      = "orgID1"
	userHeader = "X-User"
)

var (
	//go:embed testdata/sample_vc.jsonld
	sampleVCJsonLD string
	//go:embed testdata/sample_vc.jwt
	sampleVCJWT string
	//go:embed testdata/sample_vp.jsonld
	sampleVPJsonLD string
	//go:embed testdata/sample_vp.jwt
	sampleVPJWT string
)

//nolint:gochecknoglobals
var (
	verificationChecks = &profileapi.VerificationChecks{
		Credential: profileapi.CredentialChecks{
			Proof: true,
			Format: []vcsverifiable.Format{
				vcsverifiable.Jwt,
				vcsverifiable.Ldp,
			},
			Status: true,
		},
		Presentation: &profileapi.PresentationChecks{
			Proof: true,
			Format: []vcsverifiable.Format{
				vcsverifiable.Jwt,
				vcsverifiable.Ldp,
			},
		},
	}
)

func createContext(orgID string) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if orgID != "" {
		req.Header.Set("X-User", orgID)
	}

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func createContextWithBody(body []byte) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(userHeader, orgID)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestController_PostVerifyCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))

	mockVerifyCredentialSvc.EXPECT().
		VerifyCredential(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return([]verifycredential.CredentialsVerificationCheckResult{{}}, nil)

	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Verifier{
			ID:             "testId",
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyCredentialSvc: mockVerifyCredentialSvc,
		ProfileSvc:          mockProfileSvc,
		DocumentLoader:      testutil.DocumentLoader(t),
		VDR:                 &vdrmock.MockVDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLD))
		err := controller.PostVerifyCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWT))
		err := controller.PostVerifyCredentials(c, "testId")

		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyCredentials(c, "testId")

		require.Error(t, err)
	})
}

func TestController_VerifyCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	verificationResult := []verifycredential.CredentialsVerificationCheckResult{{}}
	mockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))

	mockVerifyCredentialSvc.EXPECT().
		VerifyCredential(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(verificationResult, nil)

	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Verifier{
			ID:             "testId",
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyCredentialSvc: mockVerifyCredentialSvc,
		ProfileSvc:          mockProfileSvc,
		DocumentLoader:      testutil.DocumentLoader(t),
		VDR:                 &vdrmock.MockVDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLD))

		var body VerifyCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyCredential(c, &body, "testId")
		require.NoError(t, err)
		require.Equal(t, &VerifyCredentialResponse{Checks: &[]VerifyCredentialCheckResult{{}}}, rsp)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWT))

		var body VerifyCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)
		rsp, err := controller.verifyCredential(c, &body, "testId")

		require.NoError(t, err)
		require.Equal(t, &VerifyCredentialResponse{Checks: &[]VerifyCredentialCheckResult{{}}}, rsp)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name                   string
			getCtx                 func() echo.Context
			getProfileSvc          func() profileService
			getVerifyCredentialSvc func() verifyCredentialSvc
		}{
			{
				name: "Missing authorization",
				getCtx: func() echo.Context {
					ctx := createContextWithBody([]byte(sampleVCJsonLD))
					ctx.Request().Header.Set(userHeader, "")
					return ctx
				},
				getProfileSvc: func() profileService {
					return nil
				},
				getVerifyCredentialSvc: func() verifyCredentialSvc {
					return nil
				},
			},
			{
				name: "Profile service error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVCJsonLD))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
						Return(nil, errors.New("some error"))
					return failedMockProfileSvc
				},
				getVerifyCredentialSvc: func() verifyCredentialSvc {
					return nil
				},
			},
			{
				name: "Validate credential error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(`{"credential":"","options":{}}`))
				},
				getProfileSvc: func() profileService {
					return mockProfileSvc
				},
				getVerifyCredentialSvc: func() verifyCredentialSvc {
					return nil
				},
			},
			{
				name: "Verify credential error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVCJsonLD))
				},
				getProfileSvc: func() profileService {
					return mockProfileSvc
				},
				getVerifyCredentialSvc: func() verifyCredentialSvc {
					failedMockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))
					failedMockVerifyCredentialSvc.EXPECT().
						VerifyCredential(gomock.Any(), gomock.Any(), gomock.Any()).
						AnyTimes().
						Return(nil, errors.New("some error"))
					return failedMockVerifyCredentialSvc
				},
			},
		}

		for _, testCase := range tests {
			t.Run(testCase.name, func(t *testing.T) {
				failedController := NewController(&Config{
					VerifyCredentialSvc: testCase.getVerifyCredentialSvc(),
					ProfileSvc:          testCase.getProfileSvc(),
					DocumentLoader:      testutil.DocumentLoader(t),
					VDR:                 &vdrmock.MockVDRegistry{},
				})

				var body VerifyCredentialData

				ctx := testCase.getCtx()
				err := util.ReadBody(ctx, &body)
				require.NoError(t, err)
				rsp, err := failedController.verifyCredential(ctx, &body, "testId")
				require.Error(t, err)
				require.Nil(t, rsp)
			})
		}
	})
}

func TestController_PostVerifyPresentation(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockVerifyPresSvc := NewMockverifyPresentationSvc(gomock.NewController(t))

	mockVerifyPresSvc.EXPECT().
		VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return([]verifypresentation.PresentationVerificationCheckResult{{}}, nil)

	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Verifier{
			ID:             "testId",
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   &vdrmock.MockVDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJsonLD))
		err := controller.PostVerifyPresentation(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJWT))
		err := controller.PostVerifyPresentation(c, "testId")

		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyPresentation(c, "testId")

		require.Error(t, err)
	})
}

func TestController_VerifyPresentation(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	verificationResult := []verifypresentation.PresentationVerificationCheckResult{{}}
	mockVerifyPresentationSvc := NewMockverifyPresentationSvc(gomock.NewController(t))

	mockVerifyPresentationSvc.EXPECT().
		VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(verificationResult, nil)

	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Verifier{
			ID:             "testId",
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresentationSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   &vdrmock.MockVDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJsonLD))

		var body VerifyPresentationData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyPresentation(c, &body, "testId")
		require.NoError(t, err)
		require.Equal(t, &VerifyPresentationResponse{Checks: &[]VerifyPresentationCheckResult{{}}}, rsp)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJWT))

		var body VerifyPresentationData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyPresentation(c, &body, "testId")
		require.NoError(t, err)
		require.Equal(t, &VerifyPresentationResponse{Checks: &[]VerifyPresentationCheckResult{{}}}, rsp)
	})

	t.Run("Failed", func(t *testing.T) {
		tests := []struct {
			name                     string
			getCtx                   func() echo.Context
			getProfileSvc            func() profileService
			getVerifyPresentationSvc func() verifyPresentationSvc
		}{
			{
				name: "Missing authorization",
				getCtx: func() echo.Context {
					ctx := createContextWithBody([]byte(sampleVPJsonLD))
					ctx.Request().Header.Set(userHeader, "")
					return ctx
				},
				getProfileSvc: func() profileService {
					return nil
				},
				getVerifyPresentationSvc: func() verifyPresentationSvc {
					return nil
				},
			},
			{
				name: "Profile service error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVPJsonLD))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
						Return(nil, errors.New("some error"))
					return failedMockProfileSvc
				},
				getVerifyPresentationSvc: func() verifyPresentationSvc {
					return nil
				},
			},
			{
				name: "Validate credential error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(`{"presentation":"","options":{}}`))
				},
				getProfileSvc: func() profileService {
					return mockProfileSvc
				},
				getVerifyPresentationSvc: func() verifyPresentationSvc {
					return nil
				},
			},
			{
				name: "Verify credential error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVPJsonLD))
				},
				getProfileSvc: func() profileService {
					return mockProfileSvc
				},
				getVerifyPresentationSvc: func() verifyPresentationSvc {
					failedMockVerifyPresSvc := NewMockverifyPresentationSvc(gomock.NewController(t))
					failedMockVerifyPresSvc.EXPECT().
						VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any()).
						AnyTimes().
						Return(nil, errors.New("some error"))
					return failedMockVerifyPresSvc
				},
			},
		}

		for _, testCase := range tests {
			t.Run(testCase.name, func(t *testing.T) {
				failedController := NewController(&Config{
					VerifyPresentationSvc: testCase.getVerifyPresentationSvc(),
					ProfileSvc:            testCase.getProfileSvc(),
					DocumentLoader:        testutil.DocumentLoader(t),
					VDR:                   &vdrmock.MockVDRegistry{},
				})

				var body VerifyPresentationData

				ctx := testCase.getCtx()
				err := util.ReadBody(ctx, &body)
				require.NoError(t, err)
				rsp, err := failedController.verifyPresentation(ctx, &body, "testId")
				require.Error(t, err)
				require.Nil(t, rsp)
			})
		}
	})
}

func Test_getVerifyCredentialOptions(t *testing.T) {
	type args struct {
		options *VerifyCredentialOptions
	}
	tests := []struct {
		name string
		args args
		want *verifycredential.Options
	}{
		{
			name: "Nil options",
			args: args{
				options: nil,
			},
			want: &verifycredential.Options{},
		},
		{
			name: "Challenge only",
			args: args{
				options: &VerifyCredentialOptions{
					Challenge: ptr("challenge"),
				},
			},
			want: &verifycredential.Options{
				Challenge: "challenge",
				Domain:    "",
			},
		},
		{
			name: "Domain only",
			args: args{
				options: &VerifyCredentialOptions{
					Domain: ptr("domain"),
				},
			},
			want: &verifycredential.Options{
				Challenge: "",
				Domain:    "domain",
			},
		},
		{
			name: "Challenge and Domain",
			args: args{
				options: &VerifyCredentialOptions{
					Challenge: ptr("challenge"),
					Domain:    ptr("domain"),
				},
			},
			want: &verifycredential.Options{
				Challenge: "challenge",
				Domain:    "domain",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVerifyCredentialOptions(tt.args.options); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getVerifyCredentialOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func Test_mapVerifyCredentialChecks(t *testing.T) {
	type args struct {
		checks []verifycredential.CredentialsVerificationCheckResult
	}
	tests := []struct {
		name string
		args args
		want *VerifyCredentialResponse
	}{
		{
			name: "OK",
			args: args{
				checks: []verifycredential.CredentialsVerificationCheckResult{
					{
						Check:              "check1",
						Error:              "error1",
						VerificationMethod: "verificationMethod1",
					},
					{
						Check:              "check2",
						Error:              "error2",
						VerificationMethod: "verificationMethod2",
					},
				},
			},
			want: &VerifyCredentialResponse{
				Checks: &[]VerifyCredentialCheckResult{
					{
						Check:              "check1",
						Error:              "error1",
						VerificationMethod: "verificationMethod1",
					},
					{
						Check:              "check2",
						Error:              "error2",
						VerificationMethod: "verificationMethod2",
					},
				},
			},
		},
		{
			name: "OK Empty",
			args: args{
				checks: []verifycredential.CredentialsVerificationCheckResult{},
			},
			want: &VerifyCredentialResponse{
				Checks: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapVerifyCredentialChecks(tt.args.checks); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mapVerifyCredentialChecks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mapVerifyPresentationChecks(t *testing.T) {
	type args struct {
		checks []verifypresentation.PresentationVerificationCheckResult
	}
	tests := []struct {
		name string
		args args
		want *VerifyPresentationResponse
	}{
		{
			name: "OK",
			args: args{
				checks: []verifypresentation.PresentationVerificationCheckResult{
					{
						Check: "check1",
						Error: "error1",
					},
					{
						Check: "check2",
						Error: "error2",
					},
				},
			},
			want: &VerifyPresentationResponse{
				Checks: &[]VerifyPresentationCheckResult{
					{
						Check: "check1",
						Error: "error1",
					},
					{
						Check: "check2",
						Error: "error2",
					},
				},
			},
		},
		{
			name: "OK Empty",
			args: args{
				checks: []verifypresentation.PresentationVerificationCheckResult{},
			},
			want: &VerifyPresentationResponse{
				Checks: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapVerifyPresentationChecks(tt.args.checks); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mapVerifyPresentationChecks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getVerifyPresentationOptions(t *testing.T) {
	type args struct {
		options *VerifyPresentationOptions
	}
	tests := []struct {
		name string
		args args
		want *verifypresentation.Options
	}{
		{
			name: "Nil options",
			args: args{
				options: nil,
			},
			want: &verifypresentation.Options{},
		},
		{
			name: "Challenge only",
			args: args{
				options: &VerifyPresentationOptions{
					Challenge: ptr("challenge"),
				},
			},
			want: &verifypresentation.Options{
				Challenge: "challenge",
				Domain:    "",
			},
		},
		{
			name: "Domain only",
			args: args{
				options: &VerifyPresentationOptions{
					Domain: ptr("domain"),
				},
			},
			want: &verifypresentation.Options{
				Challenge: "",
				Domain:    "domain",
			},
		},
		{
			name: "Challenge and Domain",
			args: args{
				options: &VerifyPresentationOptions{
					Challenge: ptr("challenge"),
					Domain:    ptr("domain"),
				},
			},
			want: &verifypresentation.Options{
				Challenge: "challenge",
				Domain:    "domain",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVerifyPresentationOptions(tt.args.options); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getVerifyPresentationOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func requireAuthError(t *testing.T, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, resterr.Unauthorized, actualErr.Code)
}

func requireValidationError(t *testing.T, expectedCode resterr.ErrorCode, incorrectValueName string, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, expectedCode, actualErr.Code)
	require.Equal(t, incorrectValueName, actualErr.IncorrectValue)
	require.Error(t, actualErr.Err)
}

func requireSystemError(t *testing.T, component, failedOperation string, actual error) { //nolint: unparam
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))
	require.Equal(t, resterr.SystemError, actualErr.Code)
	require.Equal(t, component, actualErr.Component)
	require.Equal(t, failedOperation, actualErr.FailedOperation)
	require.Error(t, actualErr.Err)
}

func TestController_AuthFailed(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&profileapi.Verifier{OrganizationID: orgID, SigningDID: &profileapi.SigningDID{}}, nil)

	t.Run("No token", func(t *testing.T) {
		c := createContext("")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.InitiateOidcInteraction(c, "testId")
		requireAuthError(t, err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.InitiateOidcInteraction(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "organizationID", err)
	})
}

func TestController_InitiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(&profileapi.Verifier{
		OrganizationID: orgID,
		Active:         true,
		OIDCConfig:     &profileapi.OIDC4VPConfig{},
		SigningDID:     &profileapi.SigningDID{},
		PresentationDefinitions: []*presexch.PresentationDefinition{
			&presexch.PresentationDefinition{},
		},
	}, nil)

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})
		c := createContext(orgID)
		err := controller.InitiateOidcInteraction(c, "testId")
		require.NoError(t, err)
	})
}

func TestController_initiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		result, err := controller.initiateOidcInteraction(&InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: orgID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&presexch.PresentationDefinition{},
				},
			})

		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Should be active", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(&InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: orgID,
				Active:         false,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
			})

		requireValidationError(t, resterr.ConditionNotMet, "profile.Active", err)
	})

	t.Run("Should have oidc config", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(&InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: orgID,
				Active:         true,
				OIDCConfig:     nil,
				SigningDID:     &profileapi.SigningDID{},
			})

		requireValidationError(t, resterr.ConditionNotMet, "profile.OIDCConfig", err)
	})

	t.Run("Invalid pd id", func(t *testing.T) {
		mockProfileSvcErr := NewMockProfileService(gomock.NewController(t))

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvcErr,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(&InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: orgID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
			})

		requireValidationError(t, resterr.InvalidValue, "presentationDefinitionID", err)
	})

	t.Run("oidc4VPService.InitiateOidcInteraction failed", func(t *testing.T) {
		oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any()).
			AnyTimes().Return(nil, errors.New("fail"))

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(&InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: orgID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&presexch.PresentationDefinition{},
				},
			})

		requireSystemError(t, "oidc4VPService", "InitiateOidcInteraction", err)
	})
}

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
