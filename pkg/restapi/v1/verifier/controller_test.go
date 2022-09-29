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

	profileapi "github.com/trustbloc/vcs/pkg/profile"

	"github.com/golang/mock/gomock"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
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
