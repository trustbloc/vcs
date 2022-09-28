/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
)

const (
	orgID = "orgID1"
)

//go:embed testdata/sample_vc.jsonld
var sampleVCJsonLD string

//go:embed testdata/sample_vc.jwt
var sampleVCJWT string

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

func strPtr(str string) *string {
	return &str
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
	req.Header.Set("X-User", orgID)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestController_PostIssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredsSvc := NewMockissueCredentialService(gomock.NewController(t))
	mockIssueCredsSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
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
			IssueCredentialService: mockIssueCredsSvc,
		})

		c := createContextWithBody([]byte(sampleVCJsonLD))

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
			IssueCredentialService: mockIssueCredsSvc,
		})

		c := createContextWithBody([]byte(sampleVCJWT))

		err := controller.PostIssueCredentials(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(&Config{})
		c := createContextWithBody([]byte("abc"))
		err := controller.PostIssueCredentials(c, "testId")

		requireValidationError(t, "invalid-value", "requestBody", err)
	})
}

func TestController_IssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredsSvc := NewMockissueCredentialService(gomock.NewController(t))
	mockIssueCredsSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
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
			IssueCredentialService: mockIssueCredsSvc,
		})

		c := createContextWithBody([]byte(sampleVCJsonLD))

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
			IssueCredentialService: mockIssueCredsSvc,
		})

		c := createContextWithBody([]byte(sampleVCJWT))

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
					ctx := createContextWithBody([]byte(sampleVCJsonLD))
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
					return createContextWithBody([]byte(sampleVCJsonLD))
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
					return createContextWithBody([]byte(`{"credential":"","options":{}}`))
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
					return createContextWithBody(
						[]byte(`{"credential":"","options":{"credentialStatus":{"type":"statusPurpose"}}}`))
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
					return createContextWithBody([]byte(sampleVCJsonLD))
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
					mockFailedIssueCredsSvc := NewMockissueCredentialService(gomock.NewController(t))
					mockFailedIssueCredsSvc.EXPECT().IssueCredential(
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).AnyTimes().
						Return(nil, errors.New("some error"))
					return mockFailedIssueCredsSvc
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
		c := createContext("")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.PostIssueCredentials(c, "testId")
		requireAuthError(t, err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

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
						Type: csl.StatusListCredential,
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
						Type: csl.StatusList2021Entry,
					},
					VerificationMethod: strPtr("did:trustblock:abc"),
					Created:            strPtr("02 Jan 06 15:04 MST"),
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
						Type: csl.StatusList2021Entry,
					},
					VerificationMethod: strPtr("did:trustblock:abc"),
					Created:            strPtr("1979-05-27T07:32:00Z"),
					Challenge:          strPtr("challenge"),
					Domain:             strPtr("domain"),
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
