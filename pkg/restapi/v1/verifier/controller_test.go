/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
	"go.opentelemetry.io/otel/trace"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

const (
	tenantID       = "orgID1"
	profileID      = "testProfileID"
	profileVersion = "v1.0"
	tenantIDHeader = "X-Tenant-ID"

	validAud   = "hf7d4u50e7sw6nfq8tfagyhzplgfjf2"
	validNonce = "8HIepUNFZUa-exKTrXVf4g"
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

func createContext(tenantID string) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if tenantID != "" {
		req.Header.Set("X-Tenant-ID", tenantID)
	}

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func createContextWithBody(body []byte) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(tenantIDHeader, tenantID)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func createContextApplicationForm(body []byte) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(tenantIDHeader, tenantID)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestController_PostVerifyCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))

	mockVerifyCredentialSvc.EXPECT().
		VerifyCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return([]verifycredential.CredentialsVerificationCheckResult{{}}, nil)

	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{
			ID:             profileID,
			Version:        profileVersion,
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyCredentialSvc: mockVerifyCredentialSvc,
		ProfileSvc:          mockProfileSvc,
		DocumentLoader:      testutil.DocumentLoader(t),
		VDR:                 &vdrmock.VDRegistry{},
		Tracer:              trace.NewNoopTracerProvider().Tracer(""),
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLD))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWT))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)

		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)

		require.Error(t, err)
	})
}

func TestController_VerifyCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	verificationResult := []verifycredential.CredentialsVerificationCheckResult{{}}
	mockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))

	mockVerifyCredentialSvc.EXPECT().
		VerifyCredential(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(verificationResult, nil)

	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{
			ID:             profileID,
			Version:        profileVersion,
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyCredentialSvc: mockVerifyCredentialSvc,
		ProfileSvc:          mockProfileSvc,
		DocumentLoader:      testutil.DocumentLoader(t),
		VDR:                 &vdrmock.VDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLD))

		var body VerifyCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyCredential(c.Request().Context(), &body, profileID, profileVersion, tenantID)
		require.NoError(t, err)
		require.Equal(t, &VerifyCredentialResponse{Checks: &[]VerifyCredentialCheckResult{{}}}, rsp)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWT))

		var body VerifyCredentialData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)
		rsp, err := controller.verifyCredential(c.Request().Context(), &body, profileID, profileVersion, tenantID)

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
				name: "Profile service error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVCJsonLD))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
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
						VerifyCredential(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).
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
					VDR:                 &vdrmock.VDRegistry{},
				})

				var body VerifyCredentialData

				e := testCase.getCtx()
				err := util.ReadBody(e, &body)
				require.NoError(t, err)
				rsp, err := failedController.verifyCredential(e.Request().Context(), &body, profileID, profileVersion, tenantID)
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
		VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return([]verifypresentation.PresentationVerificationCheckResult{{}}, nil, nil)

	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{
			ID:             profileID,
			Version:        profileVersion,
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   &vdrmock.VDRegistry{},
		Tracer:                trace.NewNoopTracerProvider().Tracer(""),
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJsonLD))
		err := controller.PostVerifyPresentation(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJWT))
		err := controller.PostVerifyPresentation(c, profileID, profileVersion)

		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyPresentation(c, profileID, profileVersion)

		require.Error(t, err)
	})
}

func TestController_VerifyPresentation(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	verificationResult := []verifypresentation.PresentationVerificationCheckResult{{}}
	mockVerifyPresentationSvc := NewMockverifyPresentationSvc(gomock.NewController(t))

	mockVerifyPresentationSvc.EXPECT().
		VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(verificationResult, nil, nil)

	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{
			ID:             profileID,
			Version:        profileVersion,
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresentationSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   &vdrmock.VDRegistry{},
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJsonLD))

		var body VerifyPresentationData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyPresentation(c.Request().Context(), &body, profileID, profileVersion, tenantID)
		require.NoError(t, err)
		require.Equal(t, &VerifyPresentationResponse{Checks: &[]VerifyPresentationCheckResult{{}}}, rsp)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVPJWT))

		var body VerifyPresentationData

		err := util.ReadBody(c, &body)
		require.NoError(t, err)

		rsp, err := controller.verifyPresentation(c.Request().Context(), &body, profileID, profileVersion, tenantID)
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
				name: "Profile service error",
				getCtx: func() echo.Context {
					return createContextWithBody([]byte(sampleVPJsonLD))
				},
				getProfileSvc: func() profileService {
					failedMockProfileSvc := NewMockProfileService(gomock.NewController(t))
					failedMockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
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
						VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						AnyTimes().
						Return(nil, nil, errors.New("some error"))
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
					VDR:                   &vdrmock.VDRegistry{},
				})

				var body VerifyPresentationData

				e := testCase.getCtx()
				err := util.ReadBody(e, &body)
				require.NoError(t, err)
				rsp, err := failedController.verifyPresentation(e.Request().Context(), &body, profileID, profileVersion, tenantID)
				require.Error(t, err)
				require.Nil(t, rsp)
			})
		}
	})
}

func TestController_CheckAuthorizationResponse(t *testing.T) {
	oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPService.EXPECT().VerifyOIDCVerifiablePresentation(gomock.Any(), oidc4vp.TxID("txid"), gomock.Any()).
		AnyTimes().Return(nil)

	t.Run("Success Controller JWT", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		require.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		customScopeClaims := map[string]oidc4vp.Claims{
			"customScope": {
				"key1": "value2",
			},
		}
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			CustomScopeClaims: customScopeClaims,
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
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
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
			})

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		authorisationResponseParsed, err := c.verifyAuthorizationResponseTokens(context.TODO(), &rawAuthorizationResponse{
			IDToken: signedClaimsJWTResult.JWT,
			VPToken: []string{vpToken},
			State:   "txid",
		})

		require.NoError(t, err)
		require.Equal(t, customScopeClaims, authorisationResponseParsed.CustomScopeClaims)
		require.Contains(t, authorisationResponseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")
	})

	t.Run("Success LDP", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpSigned := testutil.SignedVPWithExistingPrivateKey(t,
			&verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://identity.foundation/presentation-exchange/submission/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
				},
				Type: []string{
					"VerifiablePresentation",
					"PresentationSubmission",
				},
			},
			vcsverifiable.Ldp,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.KeyType,
			signedClaimsJWTResult.Signer,
			func(ldpc *verifiable.LinkedDataProofContext) {
				ldpc.Domain = validAud
				ldpc.Challenge = validNonce
			})

		vpToken, err := vpSigned.MarshalJSON()
		require.NoError(t, err)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		authorisationResponseParsed, err := c.verifyAuthorizationResponseTokens(context.TODO(), &rawAuthorizationResponse{
			IDToken: signedClaimsJWTResult.JWT,
			VPToken: []string{string(vpToken)},
			State:   "txid",
		})

		require.NoError(t, err)

		require.Nil(t, authorisationResponseParsed.CustomScopeClaims)
		require.Contains(t, authorisationResponseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")
	})

	t.Run("Presentation submission missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: nil},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1).DoAndReturn(
			func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)

				msg := messages[0]

				assert.Equal(t, msg.Type, spi.VerifierOIDCInteractionFailed)

				ep := &oidc4ci.EventPayload{}

				jsonData, err := json.Marshal(msg.Data.(map[string]interface{}))
				require.NoError(t, err)

				assert.NoError(t, json.Unmarshal(jsonData, ep))

				assert.Equal(t, string(resterr.InvalidValue), ep.ErrorCode)
				assert.Empty(t, ep.ErrorComponent)

				return nil
			},
		)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			DocumentLoader: testutil.DocumentLoader(t),
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token._vp_token.presentation_submission", err)
	})

	t.Run("Nonce different", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: "some_invalid",
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
				Iss:   signedClaimsJWTResult.VerMethodDID,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"nonce", err)
	})

	t.Run("Aud different", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   "some_invalid",
				Exp:   time.Now().Unix() + 1000,
				Iss:   signedClaimsJWTResult.VerMethodDID,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"aud", err)
	})

	t.Run("ID token expired", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   0,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   "some_invalid",
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token.exp", err)
	})

	t.Run("ID token invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   0,
		})

		// Signing vpToken using different key.
		vpTokenSignedJWTResult := testutil.SignedClaimsJWT(t,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   "some_invalid",
				Exp:   time.Now().Unix() + 1000,
				Iss:   signedClaimsJWTResult.VerMethodDID,
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
			})

		body := "vp_token=" + vpTokenSignedJWTResult.JWT +
			"&id_token=" + vpTokenSignedJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			// Using different key in controller.
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"id_token", err)
	})

	t.Run("VP token JWT expired", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   "some_invalid",
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   0,
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
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.exp", err)
	})

	t.Run("VP token JWT invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		// Signing vpToken using different key.
		vpTokenSignedJWTResult := testutil.SignedClaimsJWT(t,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
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
			})

		body := "vp_token=" + vpTokenSignedJWTResult.JWT +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			// Using different key in controller.
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token", err)
	})

	t.Run("VP token JWT parse VP failed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&vpTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
				VP:    &verifiable.Presentation{},
			})

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.vp", err)
	})

	t.Run("VP token LDP invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpb, err := (&verifiable.Presentation{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1",
				"https://w3id.org/security/suites/jws-2020/v1",
			},
			Type: []string{
				"VerifiablePresentation",
				"PresentationSubmission",
			},
		}).MarshalJSON()
		require.NoError(t, err)

		vpSigned := testutil.SignedVP(t,
			vpb,
			vcsverifiable.Ldp,
			func(ldpc *verifiable.LinkedDataProofContext) {
				ldpc.Domain = validAud
				ldpc.Challenge = validNonce
			})

		vpToken, err := vpSigned.Presentation.MarshalJSON()
		require.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.vp", err)
	})

	t.Run("VP token LDP challenge (nonce) missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpSigned := testutil.SignedVPWithExistingPrivateKey(t,
			&verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://identity.foundation/presentation-exchange/submission/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
				},
				Type: []string{
					"VerifiablePresentation",
					"PresentationSubmission",
				},
			},
			vcsverifiable.Ldp,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.KeyType,
			signedClaimsJWTResult.Signer,
			func(ldpc *verifiable.LinkedDataProofContext) {
				ldpc.Domain = validAud
				// ldpc.Challenge = validNonce
			})

		vpToken, err := vpSigned.MarshalJSON()
		require.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.challenge", err)
	})

	t.Run("VP token LDP domain (audience) missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t, &IDTokenClaims{
			VPToken: IDTokenVPToken{
				PresentationSubmission: map[string]interface{}{}},
			Nonce: validNonce,
			Aud:   validAud,
			Exp:   time.Now().Unix() + 1000,
		})

		vpSigned := testutil.SignedVPWithExistingPrivateKey(t,
			&verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://identity.foundation/presentation-exchange/submission/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
				},
				Type: []string{
					"VerifiablePresentation",
					"PresentationSubmission",
				},
			},
			vcsverifiable.Ldp,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.KeyType,
			signedClaimsJWTResult.Signer,
			func(ldpc *verifiable.LinkedDataProofContext) {
				// ldpc.Domain = validAud
				ldpc.Challenge = validNonce
			})

		vpToken, err := vpSigned.MarshalJSON()
		require.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireValidationError(t, resterr.InvalidValue,
			"vp_token.domain", err)
	})
}

func TestController_RetrieveInteractionsClaim(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:        "p1",
			ProfileVersion:   "v1.0",
			ReceivedClaimsID: "claims-id",
			ReceivedClaims:   &oidc4vp.ReceivedClaims{},
		}, nil)

		oidc4VPService.EXPECT().RetrieveClaims(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(map[string]oidc4vp.CredentialMetadata{}) //nolint:lll
		oidc4VPService.EXPECT().DeleteClaims(gomock.Any(), gomock.Any()).Times(1).Return(nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1", "v1.0").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				Version:        "v1.0",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.NoError(t, err)
	})

	t.Run("Success - delete claims error", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:        "p1",
			ProfileVersion:   "v1.0",
			ReceivedClaimsID: "claims-id",
			ReceivedClaims:   &oidc4vp.ReceivedClaims{},
		}, nil)

		oidc4VPService.EXPECT().RetrieveClaims(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(map[string]oidc4vp.CredentialMetadata{}) //nolint:lll
		oidc4VPService.EXPECT().DeleteClaims(gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("delete claims error"))                       //nolint:lll

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1", "v1.0").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				Version:        "v1.0",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.NoError(t, err)
	})

	t.Run("Error - claims expired", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:              "p1",
			ProfileVersion:         "v1.0",
			ReceivedClaimsID:       "claims-id",
			PresentationDefinition: &presexch.PresentationDefinition{ID: "pd1"},
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1", "v1.0").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				Version:        "v1.0",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"claims are either retrieved or expired for transaction 'txid'")
	})

	t.Run("Error - claims were never received", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:              "p1",
			ProfileVersion:         "v1.0",
			PresentationDefinition: &presexch.PresentationDefinition{ID: "pd1"},
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1", "v1.0").AnyTimes().
			Return(&profileapi.Verifier{
				ID:             "p1",
				Version:        "v1.0",
				OrganizationID: "orgID1",
				Checks:         verificationChecks,
			}, nil)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			ProfileSvc:     mockProfileSvc,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "claims were not received for transaction 'txid'")
	})

	t.Run("Tx not found", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(nil, oidc4vp.ErrDataNotFound)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireCustomError(t, resterr.TransactionNotFound, err)
	})

	t.Run("Get Tx system error", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(nil, errors.New("system error"))

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireSystemError(t, "verifier.oidc4vp-service", "GetTx", err)
	})

	t.Run("GetProfile failed", func(t *testing.T) {
		oidc4VPService := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPService.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txid")).
			Times(1).Return(&oidc4vp.Transaction{
			ProfileID:              "p1",
			ProfileVersion:         "v1.0",
			PresentationDefinition: &presexch.PresentationDefinition{},
		}, nil)

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		mockProfileSvc.EXPECT().GetProfile("p1", "v1.0").AnyTimes().
			Return(nil, errors.New("data not found"))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  oidc4VPService,
			ProfileSvc:     mockProfileSvc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireCustomError(t, resterr.ProfileNotFound, err)
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

	t.Run("Success - vp token is an array", func(t *testing.T) {
		body := "vp_token=%5B%22token1%22%2C%22token2%22%5D" +
			"&id_token=idtoken" +
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

func requireCustomError(t *testing.T, expectedCode resterr.ErrorCode, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, expectedCode, actualErr.Code)
	require.Error(t, actualErr.Err)
}

func TestController_AuthFailed(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{OrganizationID: tenantID, SigningDID: &profileapi.SigningDID{}}, nil)

	t.Run("No token", func(t *testing.T) {
		c := createContext("")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry,
			Tracer: trace.NewNoopTracerProvider().Tracer("")})

		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireAuthError(t, err)

		err = controller.RetrieveInteractionsClaim(c, "txid")
		requireAuthError(t, err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry,
			Tracer: trace.NewNoopTracerProvider().Tracer("")})

		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireCustomError(t, resterr.ProfileNotFound, err)
	})
}

func TestController_InitiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Times(1).Return(&profileapi.Verifier{
			OrganizationID: tenantID,
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
			Tracer:        trace.NewNoopTracerProvider().Tracer(""),
		})
		c := createContext(tenantID)
		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		require.NoError(t, err)
	})

	t.Run("Profile not found", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Times(1).Return(nil, nil)

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
			Tracer:        trace.NewNoopTracerProvider().Tracer(""),
		})
		c := createContext(tenantID)
		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireCustomError(t, resterr.ProfileNotFound, err)
	})
}

func TestController_initiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(
		gomock.Any(), gomock.Any(), gomock.Any(), []string{"test_scope"}, gomock.Any()).
		AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		result, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{
			Scopes: lo.ToPtr([]string{"test_scope"}),
		},
			&profileapi.Verifier{
				OrganizationID: tenantID,
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

	t.Run("Success - With Presentation Definition and PD filters", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		fields := []string{""}

		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		result, err := controller.initiateOidcInteraction(context.TODO(),
			&InitiateOIDC4VPData{
				Scopes: lo.ToPtr([]string{"test_scope"}),
				PresentationDefinitionFilters: &PresentationDefinitionFilters{
					Fields: &fields,
				},
			},
			&profileapi.Verifier{
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&pd,
				},
			})

		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Success - With Multiple Presentation Definitions, "+
		"Not Empty Presentation Definition ID and PD filters", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		fields := []string{""}

		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		var pd2 presexch.PresentationDefinition

		err = json.Unmarshal([]byte(testPD), &pd2)
		require.NoError(t, err)

		pd2.ID = "some-id"

		pdID := "some-id"

		result, err := controller.initiateOidcInteraction(context.TODO(),
			&InitiateOIDC4VPData{
				Scopes:                   lo.ToPtr([]string{"test_scope"}),
				PresentationDefinitionId: &pdID,
				PresentationDefinitionFilters: &PresentationDefinitionFilters{
					Fields: &fields,
				},
			},
			&profileapi.Verifier{
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&pd, &pd2,
				},
			})

		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Error - With Multiple Presentation Definitions, "+
		"Empty Presentation Definition ID, PD filters", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		fields := []string{""}

		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		var pd2 presexch.PresentationDefinition

		err = json.Unmarshal([]byte(testPD), &pd2)
		require.NoError(t, err)

		pd2.ID = "some-other-id"

		result, err := controller.initiateOidcInteraction(context.TODO(),
			&InitiateOIDC4VPData{
				PresentationDefinitionFilters: &PresentationDefinitionFilters{
					Fields: &fields,
				},
			},
			&profileapi.Verifier{
				ID:             "profile-id",
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&pd, &pd2,
				},
			})

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(),
			"invalid-value[presentationDefinitionID]: presentation definition id= not found for profile with id=profile-id")
	})

	t.Run("Should be active", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: tenantID,
				Active:         false,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
			})

		requireCustomError(t, resterr.ProfileInactive, err)
	})

	t.Run("Error - With Presentation Definition and PD filters", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		const invalidRegex = "^(#[=+[.rst:)$*"

		fields := []string{invalidRegex}

		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		require.NoError(t, err)

		result, err := controller.initiateOidcInteraction(context.TODO(),
			&InitiateOIDC4VPData{
				PresentationDefinitionFilters: &PresentationDefinitionFilters{
					Fields: &fields,
				},
			},
			&profileapi.Verifier{
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&pd,
				},
			})

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "invalid-value[presentationDefinitionFilters]: failed to compile regex")
	})

	t.Run("Should have oidc config", func(t *testing.T) {
		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: tenantID,
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
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
			})

		requireValidationError(t, resterr.InvalidValue, "presentationDefinitionID", err)
	})

	t.Run("oidc4VPService.InitiateOidcInteraction failed", func(t *testing.T) {
		oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPSvc.EXPECT().
			InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			AnyTimes().Return(nil, errors.New("fail"))

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
		})

		_, err := controller.initiateOidcInteraction(context.TODO(), &InitiateOIDC4VPData{},
			&profileapi.Verifier{
				OrganizationID: tenantID,
				Active:         true,
				OIDCConfig:     &profileapi.OIDC4VPConfig{},
				SigningDID:     &profileapi.SigningDID{},
				PresentationDefinitions: []*presexch.PresentationDefinition{
					&presexch.PresentationDefinition{},
				},
			})

		requireSystemError(t, "verifier.oidc4vp-service", "InitiateOidcInteraction", err)
	})
}

func TestMatchField(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		_, matched, err := matchField(nil, "id")
		require.NoError(t, err)
		require.False(t, matched)
	})
}

func TestCopyPresentationDefinition(t *testing.T) {
	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd *presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		require.NoError(t, err)

		copied, err := copyPresentationDefinition(pd)
		require.NoError(t, err)
		require.Equal(t, pd, copied)
	})
}

func TestApplyFieldsFilter(t *testing.T) {
	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		require.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{"degree_type_id"})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 0)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Fail - field not found", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		require.NoError(t, err)

		_, err = applyFieldsFilter(&pd, []string{"degree_type_id", "random_field"})
		require.ErrorContains(t, err, "field random_field not found")
	})

	t.Run("Success - empty string filter(accept fields with empty ID)", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{""})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		require.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{"degree_type_id"})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 0)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test prefix filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		const testPrefix = "*_test_prefix"

		pd.InputDescriptors[0].Constraints.Fields[0].ID = testPrefix + "_first"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = testPrefix + "_second"

		result, err := applyFieldsFilter(&pd, []string{testPrefix})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Fail - test invalid regex", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		const testPrefix = `*[ ]\K(?<!\d )(?=(?: ?\d){8})(?!(?: ?\d){9})\d[ \d]+\d`

		pd.InputDescriptors[0].Constraints.Fields[0].ID = testPrefix + "_first"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = testPrefix + "_second"

		_, err = applyFieldsFilter(&pd, []string{testPrefix})
		require.ErrorContains(t, err, "failed to compile regex")
	})

	t.Run("Success - test suffix filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		const testSuffix = "test_suffix_*"

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first" + testSuffix
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second" + testSuffix

		result, err := applyFieldsFilter(&pd, []string{testSuffix})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first_group_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second_group_addon_id"

		result, err := applyFieldsFilter(&pd, []string{"*group*"})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first_group_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second_group_addon_id"

		result, err := applyFieldsFilter(&pd, []string{"*group*"})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "prefix_first_group_a_suffix"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "prefix_second_group_b_suffix"

		result, err := applyFieldsFilter(&pd, []string{"prefix*group*suffix"})
		require.NoError(t, err)

		require.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		require.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Error - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		require.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "prefix_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "suffix_id"

		const invalidRegex = "^(#[=+[.rst:)$*"

		result, err := applyFieldsFilter(&pd, []string{invalidRegex})
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to compile regex")
	})
}

type vpTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Aud   string                   `json:"aud"`
	Iss   string                   `json:"iss"`
	Exp   int64                    `json:"exp"`
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

const testPD = `
{
  "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
  "input_descriptors": [
    {
      "id": "type",
      "name": "type",
      "purpose": "We can only interact with specific status information for Verifiable Credentials",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialStatus.type",
              "$.vc.credentialStatus.type"
            ],
            "purpose": "We can only interact with specific status information for Verifiable Credentials",
            "filter": {
              "type": "string",
              "enum": [
                "StatusList2021Entry",
                "RevocationList2021Status",
                "RevocationList2020Status"
              ]
            }
          }
        ]
      }
    },
    {
      "id": "degree",
      "name": "degree",
      "purpose": "We can only hire with bachelor degree.",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialSubject.degree.type",
              "$.vc.credentialSubject.degree.type"
            ],
            "purpose": "We can only hire with bachelor degree.",
            "filter": {
              "type": "string",
              "const": "BachelorDegree"
            }
          }
        ]
      }
    }
  ]
}`

const testPDWithFieldIDs = `
{
  "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
  "input_descriptors": [
    {
      "id": "type",
      "name": "type",
      "purpose": "We can only interact with specific status information for Verifiable Credentials",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialStatus.type",
              "$.vc.credentialStatus.type"
            ],
			"id": "credential_status_type_id",
            "purpose": "We can only interact with specific status information for Verifiable Credentials",
            "filter": {
              "type": "string",
              "enum": [
                "StatusList2021Entry",
                "RevocationList2021Status",
                "RevocationList2020Status"
              ]
            }
          }
        ]
      }
    },
    {
      "id": "degree",
      "name": "degree",
      "purpose": "We can only hire with bachelor degree.",
      "schema": [
        {
          "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints": {
        "fields": [
          {
            "path": [
              "$.credentialSubject.degree.type",
              "$.vc.credentialSubject.degree.type"
            ],
			"id": "degree_type_id",
            "purpose": "We can only hire with bachelor degree.",
            "filter": {
              "type": "string",
              "const": "BachelorDegree"
            }
          }
        ]
      }
    }
  ]
}`
