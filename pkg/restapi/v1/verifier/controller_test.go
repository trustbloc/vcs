/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
			Strict: true,
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

func createContextApplicationForm(body []byte) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
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

func generateToken(t *testing.T, claims interface{}, privKey ed25519.PrivateKey) string {
	token, err := jwt.NewSigned(claims, nil, jwt.NewEd25519Signer(privKey))
	require.NoError(t, err)
	jws, err := token.Serialize(false)
	require.NoError(t, err)

	return jws
}

func TestController_CheckAuthorizationResponse(t *testing.T) {
	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	v, e := jwt.NewEd25519Verifier(pubKey)
	require.NoError(t, e)

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: v,
	})

	oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPService.EXPECT().VerifyOIDCVerifiablePresentation(oidc4vp.TxID("txid"), gomock.Any()).
		AnyTimes().Return(nil)

	t.Run("Success", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP: &verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://identity.foundation/presentation-exchange/submission/v1",
				},
				Type: []string{
					"VerifiablePresentation",
					"PresentationSubmission",
				},
			},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			JWTVerifier:    sVerifier,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.CheckAuthorizationResponse(ctx)
		require.NoError(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP: &verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://identity.foundation/presentation-exchange/submission/v1",
				},
				Type: []string{
					"VerifiablePresentation",
					"PresentationSubmission",
				},
			},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			JWTVerifier:    sVerifier,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		processedVPToken, err := c.verifyAuthorizationResponseTokens(&authorizationResponse{
			IDToken: idToken,
			VPToken: vpToken,
			State:   "txid",
		})

		require.NoError(t, err)
		require.Contains(t, processedVPToken.Presentation.Type, "PresentationSubmission")
	})

	t.Run("Presentation submission missed", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token._vp_token.presentation_submission", err)
	})

	t.Run("Nonce different", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "bbb",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"nonce", err)
	})

	t.Run("ID token expired", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   0,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token.exp", err)
	})

	t.Run("ID token invalid signature", func(t *testing.T) {
		_, privKeyOther, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKeyOther)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKeyOther)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token", err)
	})

	t.Run("Presentation token expired", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "aaa",
			Exp:   0,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.exp", err)
	})

	t.Run("Presentation token invalid signature", func(t *testing.T) {
		_, privKeyOther, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &vpTokenClaims{
			VP:    &verifiable.Presentation{},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKeyOther)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token", err)
	})

	t.Run("Presentation token invalid signature", func(t *testing.T) {
		idToken := generateToken(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		vpToken := generateToken(t, &VPTokenClaims{
			Nonce: "aaa",
			Exp:   time.Now().Unix() + 1000,
		}, privKey)

		body := "vp_token=" + vpToken +
			"&id_token=" + idToken +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		c := NewController(&Config{
			OIDCVPService: oidc4VPService,
			JWTVerifier:   sVerifier,
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.vp", err)
	})
}

func TestController_RetrieveInteractionsClaim(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:        "p1",
			ReceivedClaimsID: "claims-id",
			ReceivedClaims:   &oidc4vp.ReceivedClaims{},
		}, nil)

		oidc4VPService.EXPECT().RetrieveClaims(gomock.Any()).Times(1).Return(map[string]oidc4vp.CredentialMetadata{})

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.NoError(t, err)
	})

	t.Run("Error - claims expired", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:        "p1",
			ReceivedClaimsID: "claims-id",
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "claims expired for transaction 'txid'")
	})

	t.Run("Error - claims were never received", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID: "p1",
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "claims were not received for transaction 'txid'")
	})

	t.Run("Tx not found", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(nil, oidc4vp.ErrDataNotFound)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireValidationError(t, resterr.DoesntExist, "txID", err)
	})

	t.Run("Get Tx system error", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(nil, errors.New("system error"))

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireSystemError(t, "oidc4vp.Service", "GetTx", err)
	})

	t.Run("GetProfile failed", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID: "p1",
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1").AnyTimes().
			Return(nil, errors.New("data not found"))

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})
}

func TestController_validateAuthorizationResponse(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		body := "vp_token=toke1&" +
			"&id_token=toke2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		ar, err := validateAuthorizationResponse(ctx)
		require.NoError(t, err)
		require.NotNil(t, ar)
	})

	t.Run("Missed id_token", func(t *testing.T) {
		body := "vp_token=v1&" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "id_token", err)
	})

	t.Run("Duplicated id_token", func(t *testing.T) {
		body := "vp_token=v1&" +
			"id_token=1&id_token=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "id_token", err)
	})

	t.Run("Missed vp_token", func(t *testing.T) {
		body := "id_token=v1&" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "vp_token", err)
	})

	t.Run("Duplicated vp_token", func(t *testing.T) {
		body := "id_token=v1&" +
			"vp_token=1&vp_token=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "vp_token", err)
	})

	t.Run("Missed state", func(t *testing.T) {
		body := "id_token=v1&" +
			"&vp_token=t"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "state", err)
	})

	t.Run("Duplicated state", func(t *testing.T) {
		body := "id_token=v1&" +
			"vp_token=1&state=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := validateAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue, "state", err)
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

		err = controller.RetrieveInteractionsClaim(c, "testId")
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

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(&profileapi.Verifier{
			OrganizationID: orgID,
			Active:         true,
			OIDCConfig:     &profileapi.OIDC4VPConfig{},
			SigningDID:     &profileapi.SigningDID{},
			PresentationDefinitions: []*presexch.PresentationDefinition{
				&presexch.PresentationDefinition{},
			},
		}, nil)

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})
		c := createContext(orgID)
		err := controller.InitiateOidcInteraction(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Profile not found", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil, nil)

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})
		c := createContext(orgID)
		err := controller.InitiateOidcInteraction(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})
}

func TestController_initiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		result, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
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

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
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

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
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

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
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
		oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			AnyTimes().Return(nil, errors.New("fail"))

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
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

type vpTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Exp   int64                    `json:"exp"`
	Iss   string                   `json:"iss"`
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
