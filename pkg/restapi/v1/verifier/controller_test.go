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
	"encoding/base64"
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
	"github.com/trustbloc/did-go/doc/did"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/verifiable/lddocument"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
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
	//go:embed testdata/sample_vc_jsonld_request.json
	sampleVCJsonLDReq string
	//go:embed testdata/sample_vc_jwt_request.json
	sampleVCJWTReq string
	//go:embed testdata/sample_vp_jsonld_request.json
	sampleVPJsonLDReq string
	//go:embed testdata/sample_vp.jsonld
	sampleVPJsonLD []byte
	//go:embed testdata/sample_vp.jwt
	sampleVPJWT []byte
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
		Tracer:              nooptracer.NewTracerProvider().Tracer(""),
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLDReq))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)
		assert.NoError(t, err)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWTReq))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)

		assert.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)

		assert.Error(t, err)
	})
}

func TestController_PostVerifyCredentialsErr(t *testing.T) {
	t.Run("HasError", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockVerifyCredentialSvc := NewMockVerifyCredentialService(gomock.NewController(t))

		mockVerifyCredentialSvc.EXPECT().
			VerifyCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			AnyTimes().
			Return([]verifycredential.CredentialsVerificationCheckResult{
				{
					Error: "error",
				},
			}, nil)

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
			Tracer:              nooptracer.NewTracerProvider().Tracer(""),
		})

		c := createContextWithBody([]byte(sampleVCJsonLDReq))
		err := controller.PostVerifyCredentials(c, profileID, profileVersion)
		assert.NoError(t, err)
		assert.EqualValues(t, c.Response().Status, http.StatusBadRequest)
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
		c := createContextWithBody([]byte(sampleVCJsonLDReq))

		var body VerifyCredentialData

		err := c.Bind(&body)
		assert.NoError(t, err)

		rsp, err := controller.verifyCredential(c.Request().Context(), &body, profileID, profileVersion, tenantID)
		assert.Nil(t, err)
		assert.Equal(t, &VerifyCredentialResponse{Checks: &[]VerifyCredentialCheckResult{{}}}, rsp)
	})

	t.Run("Missing credential", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJsonLDReq))

		var body VerifyCredentialData

		err := c.Bind(&body)
		assert.NoError(t, err)

		body.VerifiableCredential = nil
		body.Credential = nil

		rsp, err := controller.verifyCredential(c.Request().Context(), &body, profileID, profileVersion, tenantID)
		assert.ErrorContains(t, err, "missing credential")
		assert.Nil(t, rsp)
	})

	t.Run("Success JWT", func(t *testing.T) {
		c := createContextWithBody([]byte(sampleVCJWTReq))

		var body VerifyCredentialData

		err := c.Bind(&body)
		assert.NoError(t, err)
		rsp, err := controller.verifyCredential(c.Request().Context(), &body, profileID, profileVersion, tenantID)

		assert.Nil(t, err)
		assert.Equal(t, &VerifyCredentialResponse{Checks: &[]VerifyCredentialCheckResult{{}}}, rsp)
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
					return createContextWithBody([]byte(sampleVCJsonLDReq))
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
					return createContextWithBody([]byte(sampleVCJsonLDReq))
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
				err := e.Bind(&body)
				assert.NoError(t, err)
				rsp, err := failedController.verifyCredential(e.Request().Context(), &body, profileID, profileVersion, tenantID)
				assert.Error(t, err)
				assert.Nil(t, rsp)
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
		Return(verifypresentation.PresentationVerificationResult{}, nil, nil)

	mockProfileSvc.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().
		Return(&profileapi.Verifier{
			ID:             profileID,
			Version:        profileVersion,
			OrganizationID: "orgID1",
			Checks:         verificationChecks,
		}, nil)

	didDoc, pubKey := createDIDDoc(t)

	mockVDR := &vdrmock.VDRegistry{
		CreateValue: didDoc,
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == didDoc.ID {
				return &did.DocResolution{DIDDocument: didDoc}, nil
			}

			return nil, fmt.Errorf("fail to resolve did %s", didID)
		},
	}

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t,
		[]*testsupport.SigningKey{
			{Type: kms.ED25519Type, PublicKeyID: didDoc.VerificationMethod[0].ID, PublicKey: pubKey},
		},
	)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   mockVDR,
		ProofChecker:          proofChecker,
		Tracer:                nooptracer.NewTracerProvider().Tracer(""),
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		vp := createVP(t, sampleVPJsonLD, proofCreators[0], didDoc.VerificationMethod[0].ID)

		body, err := json.Marshal(&VerifyPresentationData{VerifiablePresentation: vp})
		require.NoError(t, err)

		err = controller.PostVerifyPresentation(createContextWithBody(body), profileID, profileVersion)
		assert.NoError(t, err)
	})
	t.Run("Success JWT", func(t *testing.T) {
		vp := createVP(t, sampleVPJsonLD, proofCreators[0], didDoc.VerificationMethod[0].ID)

		body, err := json.Marshal(&VerifyPresentationData{VerifiablePresentation: vp})
		require.NoError(t, err)

		err = controller.PostVerifyPresentation(createContextWithBody(body), profileID, profileVersion)
		assert.NoError(t, err)
	})
	t.Run("Failed", func(t *testing.T) {
		c := createContextWithBody([]byte("abc"))
		err := controller.PostVerifyPresentation(c, profileID, profileVersion)

		assert.Error(t, err)
	})
}

func createDIDDoc(t *testing.T) (*did.Doc, ed25519.PublicKey) {
	t.Helper()

	const (
		didContext = "https://w3id.org/did/v1"
		didID      = "did:local:abc"
		creator    = didID + "#key-1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verMethod := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:            []string{didContext},
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{verMethod},
		Created:            &createdTime,
	}, pubKey
}

func createVP(
	t *testing.T,
	vpData []byte,
	proofCreator lddocument.ProofCreator,
	verMethod string,
) *verifiable.Presentation {
	t.Helper()

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		KeyType:                 kms.ED25519Type,
		SignatureRepresentation: verifiable.SignatureJWS,
		ProofCreator:            proofCreator,
		VerificationMethod:      verMethod,
	}

	vp, err := verifiable.ParsePresentation(vpData,
		verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithPresDisabledProofCheck(),
	)
	require.NoError(t, err)

	vp.Holder = vp.Credentials()[0].Contents().Issuer.ID
	err = vp.Credentials()[0].AddLinkedDataProof(ldpContext,
		ldprocessor.WithDocumentLoader(testutil.DocumentLoader(t)))
	require.NoError(t, err)

	err = vp.AddLinkedDataProof(ldpContext,
		ldprocessor.WithDocumentLoader(testutil.DocumentLoader(t)))
	require.NoError(t, err)

	return vp
}

func TestController_VerifyPresentation(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	verificationResult := verifypresentation.PresentationVerificationResult{
		Checks: []*verifypresentation.Check{
			{
				Check: "proof",
			},
		},
	}
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

	didDoc, pubKey := createDIDDoc(t)

	mockVDR := &vdrmock.VDRegistry{
		CreateValue: didDoc,
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == didDoc.ID {
				return &did.DocResolution{DIDDocument: didDoc}, nil
			}

			return nil, fmt.Errorf("fail to resolve did %s", didID)
		},
	}

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t,
		[]*testsupport.SigningKey{
			{Type: kms.ED25519Type, PublicKeyID: didDoc.VerificationMethod[0].ID, PublicKey: pubKey},
		},
	)

	controller := NewController(&Config{
		VerifyPresentationSvc: mockVerifyPresentationSvc,
		ProfileSvc:            mockProfileSvc,
		DocumentLoader:        testutil.DocumentLoader(t),
		VDR:                   mockVDR,
		ProofChecker:          proofChecker,
	})

	t.Run("Success JSON-LD", func(t *testing.T) {
		vp := createVP(t, sampleVPJsonLD, proofCreators[0], didDoc.VerificationMethod[0].ID)

		b, err := json.Marshal(&VerifyPresentationData{VerifiablePresentation: vp})
		require.NoError(t, err)

		c := createContextWithBody(b)

		var body VerifyPresentationData

		err = c.Bind(&body)
		assert.NoError(t, err)

		rsp, err := controller.verifyPresentation(c.Request().Context(), &body, profileID, profileVersion, tenantID)

		assert.Nil(t, err)
		assert.Len(t, rsp.Checks, 1)
		assert.Len(t, lo.FromPtr(rsp.Errors), 0)
	})

	t.Run("Success JWT", func(t *testing.T) {
		vp := createVP(t, sampleVPJWT, proofCreators[0], didDoc.VerificationMethod[0].ID)

		b, err := json.Marshal(&VerifyPresentationData{VerifiablePresentation: vp})
		require.NoError(t, err)

		c := createContextWithBody(b)

		var body VerifyPresentationData

		err = c.Bind(&body)
		assert.NoError(t, err)

		rsp, err := controller.verifyPresentation(c.Request().Context(), &body, profileID, profileVersion, tenantID)
		assert.Nil(t, err)

		assert.Len(t, rsp.Checks, 1)
		assert.Len(t, lo.FromPtr(rsp.Errors), 0)
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
					return createContextWithBody([]byte(sampleVPJsonLDReq))
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
					return createContextWithBody([]byte(sampleVPJsonLDReq))
				},
				getProfileSvc: func() profileService {
					return mockProfileSvc
				},
				getVerifyPresentationSvc: func() verifyPresentationSvc {
					failedMockVerifyPresSvc := NewMockverifyPresentationSvc(gomock.NewController(t))
					failedMockVerifyPresSvc.EXPECT().
						VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						AnyTimes().
						Return(verifypresentation.PresentationVerificationResult{}, nil, errors.New("some error"))
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
				err := e.Bind(&body)
				assert.NoError(t, err)
				rsp, err := failedController.verifyPresentation(e.Request().Context(), &body, profileID, profileVersion, tenantID)
				assert.Error(t, err)
				assert.Nil(t, rsp)
			})
		}
	})
}

func TestController_CheckAuthorizationResponse(t *testing.T) {
	svc := NewMockOIDC4VPService(gomock.NewController(t))
	svc.EXPECT().VerifyOIDCVerifiablePresentation(gomock.Any(), oidc4vp.TxID("txid"), gomock.Any()).
		AnyTimes().Return(nil)

	t.Run("Success JWT", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		assert.NoError(t, err)
	})

	t.Run("Success LDP", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpSigned := testutil.SignedVPWithExistingPrivateKey(t,
			&verifiable.Presentation{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
				},
				Type: []string{
					"VerifiablePresentation",
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
		assert.NoError(t, err)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		authorisationResponseParsed, err := c.verifyAuthorizationResponseTokens(context.TODO(),
			&rawAuthorizationResponse{
				IDToken:                signedClaimsJWTResult.JWT,
				VPToken:                []string{string(vpToken)},
				PresentationSubmission: string(presentationSubmission),
				State:                  "txid",
				InteractionDetails: map[string]interface{}{
					"key1": "value1",
				},
			},
		)

		assert.Nil(t, err)

		assert.Nil(t, authorisationResponseParsed.CustomScopeClaims)
		assert.Contains(t, authorisationResponseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")
		assert.Equal(t, map[string]interface{}{"key1": "value1"}, authorisationResponseParsed.InteractionDetails)
	})

	t.Run("Success LDP With Attachments", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
				Attachments: map[string]string{
					"id1": "data:image/svg;base64,YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9jYXQucG5n",
				},
			},
		)

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
		assert.NoError(t, err)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(0)

		c := NewController(&Config{
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		authorisationResponseParsed, err := c.verifyAuthorizationResponseTokens(context.TODO(),
			&rawAuthorizationResponse{
				IDToken:                signedClaimsJWTResult.JWT,
				VPToken:                []string{string(vpToken)},
				PresentationSubmission: string(presentationSubmission),
				State:                  "txid",
			},
		)

		assert.Nil(t, err)

		assert.Nil(t, authorisationResponseParsed.CustomScopeClaims)
		assert.Contains(t, authorisationResponseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")

		assert.Len(t, authorisationResponseParsed.Attachments, 1)
		assert.EqualValues(t, "data:image/svg;base64,YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9jYXQucG5n",
			authorisationResponseParsed.Attachments["id1"])
		assert.Nil(t, authorisationResponseParsed.InteractionDetails)
	})

	t.Run("Success JWT ID1", func(t *testing.T) {
		customScopeClaims := map[string]oidc4vp.Claims{
			"customScope": {
				"key1": "value2",
			},
		}

		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&idTokenClaimsID1{
				CustomScopeClaims: customScopeClaims,
				VPToken: idTokenVPToken{
					PresentationSubmission: map[string]interface{}{},
				},
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		responseParsed, err := c.verifyAuthorizationResponseTokens(context.Background(),
			&rawAuthorizationResponse{
				IDToken: signedClaimsJWTResult.JWT,
				VPToken: []string{vpToken},
				State:   "txid",
			},
		)

		assert.Nil(t, err)
		assert.Equal(t, customScopeClaims, responseParsed.CustomScopeClaims)
		assert.Contains(t, responseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")
		assert.Nil(t, responseParsed.InteractionDetails)
	})

	t.Run("Success CWT", func(t *testing.T) {
		customScopeClaims := map[string]oidc4vp.Claims{
			"customScope": {
				"key1": "value2",
			},
		}

		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&idTokenClaimsID1{
				CustomScopeClaims: customScopeClaims,
				VPToken: idTokenVPToken{
					PresentationSubmission: map[string]interface{}{},
				},
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsCWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
		})

		responseParsed, err := c.verifyAuthorizationResponseTokens(context.Background(),
			&rawAuthorizationResponse{
				IDToken: signedClaimsJWTResult.JWT,
				VPToken: []string{vpToken},
				State:   "txid",
			},
		)

		assert.Nil(t, err)
		assert.Equal(t, customScopeClaims, responseParsed.CustomScopeClaims)
		assert.Contains(t, responseParsed.VPTokens[0].Presentation.Type, "PresentationSubmission")
		assert.Nil(t, responseParsed.InteractionDetails)
	})

	t.Run("Success error AR response", func(t *testing.T) {
		interactionDetails := base64.StdEncoding.EncodeToString([]byte(`{"key1":"value1"}`))

		body := "error=invalid_request" +
			"&error_description=unsupported%20client_id_scheme" +
			"&state=txid" +
			"&interaction_details=" + interactionDetails

		ctx := createContextApplicationForm([]byte(body))

		svc.EXPECT().HandleWalletNotification(gomock.Any(), &oidc4vp.WalletNotification{
			TxID:               oidc4vp.TxID("txid"),
			Error:              "invalid_request",
			ErrorDescription:   "unsupported client_id_scheme",
			InteractionDetails: map[string]interface{}{"key1": "value1"},
		}).Return(nil)

		c := NewController(&Config{
			OIDCVPService: svc,
			Tracer:        nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		assert.NoError(t, err)
	})

	t.Run("Error: failed to HandleWalletNotification", func(t *testing.T) {
		body := "error=invalid_request" +
			"&error_description=unsupported%20client_id_scheme" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		svc.EXPECT().HandleWalletNotification(gomock.Any(), &oidc4vp.WalletNotification{
			TxID:             oidc4vp.TxID("txid"),
			Error:            "invalid_request",
			ErrorDescription: "unsupported client_id_scheme",
		}).Return(errors.New("handle wallet notification error"))

		c := NewController(&Config{
			OIDCVPService: svc,
			Tracer:        nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		assert.ErrorContains(t, err, "handle wallet notification error")
	})

	t.Run("Presentation submission missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

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

				jsonData, err := json.Marshal(msg.Data)
				assert.NoError(t, err)

				assert.NoError(t, json.Unmarshal(jsonData, ep))

				assert.Equal(t, "bad_request", ep.ErrorCode)
				assert.Equal(t, resterr.VerifierOIDC4vpSvcComponent, resterr.Component(ep.ErrorComponent))

				return nil
			},
		)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			DocumentLoader: testutil.DocumentLoader(t),
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "presentation_submission", err)
	})

	t.Run("Presentation submission invalid", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=invalid" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.CheckAuthorizationResponse(ctx)

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "presentation_submission", err)
	})

	t.Run("Nonce different", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "nonce", err)
	})

	t.Run("Aud different", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "aud", err)
	})

	t.Run("ID token expired", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   0,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "id_token.exp", err)
	})

	t.Run("ID token invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   0,
			},
		)

		// Signing vpToken using different key.
		vpTokenSignedJWTResult := testutil.SignedClaimsJWT(t,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpTokenSignedJWTResult.JWT +
			"&id_token=" + vpTokenSignedJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			// Using different key in controller.
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "id_token", err)
	})

	t.Run("VP token JWT expired", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token.exp", err)
	})

	t.Run("VP token JWT invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		// Signing vpToken using different key.
		vpTokenSignedJWTResult := testutil.SignedClaimsJWT(t,
			&VPTokenClaims{
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
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpTokenSignedJWTResult.JWT +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			// Using different key in controller.
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token", err)
	})

	t.Run("VP token JWT parse VP failed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

		vpToken := testutil.SignedClaimsJWTWithExistingPrivateKey(t,
			signedClaimsJWTResult.VerMethodDIDKeyID,
			signedClaimsJWTResult.Signer,
			&VPTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Iss:   signedClaimsJWTResult.VerMethodDID,
				Exp:   time.Now().Unix() + 1000,
				VP:    &verifiable.Presentation{},
			},
		)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + vpToken +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			VDR:            signedClaimsJWTResult.VDR,
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token.vp", err)
	})

	t.Run("VP token LDP invalid signature", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

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
		assert.NoError(t, err)

		vpSigned := testutil.SignedVP(t,
			vpb,
			vcsverifiable.Ldp,
			func(ldpc *verifiable.LinkedDataProofContext) {
				ldpc.Domain = validAud
				ldpc.Challenge = validNonce
			})

		vpToken, err := vpSigned.Presentation.MarshalJSON()
		assert.NoError(t, err)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token", err)
	})

	t.Run("VP token LDP challenge (nonce) missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

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
		assert.NoError(t, err)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token.challenge", err)
	})

	t.Run("VP token LDP domain (audience) missed", func(t *testing.T) {
		signedClaimsJWTResult := testutil.SignedClaimsJWT(t,
			&IDTokenClaims{
				Nonce: validNonce,
				Aud:   validAud,
				Exp:   time.Now().Unix() + 1000,
			},
		)

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
		assert.NoError(t, err)

		presentationSubmission, err := json.Marshal(map[string]interface{}{})
		assert.NoError(t, err)

		body := "vp_token=" + string(vpToken) +
			"&id_token=" + signedClaimsJWTResult.JWT +
			"&presentation_submission=" + string(presentationSubmission) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(1)

		c := NewController(&Config{
			OIDCVPService:  svc,
			EventSvc:       mockEventSvc,
			EventTopic:     spi.VerifierEventTopic,
			VDR:            signedClaimsJWTResult.VDR,
			DocumentLoader: testutil.DocumentLoader(t),
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err = c.CheckAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "vp_token.domain", err)
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		assert.NoError(t, err)
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		assert.NoError(t, err)
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(),
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "claims were not received for transaction 'txid'")
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireOidc4VpError(t, "bad_request", resterr.VerifierTxnMgrComponent, "", "", err)
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "", err)
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		err := c.RetrieveInteractionsClaim(createContext("orgID1"), "txid")
		requireOidc4VpError(t, "bad_request", "", "", "", err)
	})
}

func TestController_decodeAuthorizationResponse(t *testing.T) {
	t.Run("Success: without interaction details", func(t *testing.T) {
		body := "vp_token=toke1&" +
			"&id_token=toke2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		ar, err := decodeAuthorizationResponse(ctx)
		assert.Nil(t, err)
		assert.NotNil(t, ar)
	})

	t.Run("Success: with interaction details", func(t *testing.T) {
		interactionDetails := map[string]interface{}{
			"key1": "value1",
		}
		interactionDetailsBytes, err := json.Marshal(interactionDetails)
		assert.NoError(t, err)

		body := "vp_token=toke1&" +
			"&id_token=toke2" +
			"&interaction_details=" + base64.StdEncoding.EncodeToString(interactionDetailsBytes) +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		ar, err := decodeAuthorizationResponse(ctx)
		assert.Nil(t, err)
		assert.NotNil(t, ar)
	})

	t.Run("Success: authorization error response", func(t *testing.T) {
		body := "error=invalid_request" +
			"&error_description=unsupported%20client_id_scheme" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		ar, err := decodeAuthorizationResponse(ctx)
		assert.Nil(t, err)
		assert.NotNil(t, ar)

		assert.Equal(t, ar.State, "txid")
		assert.Equal(t, ar.Error, "invalid_request")
		assert.Equal(t, ar.ErrorDescription, "unsupported client_id_scheme")
	})

	t.Run("Success - vp token is an array", func(t *testing.T) {
		body := "vp_token=%5B%22token1%22%2C%22token2%22%5D" +
			"&id_token=idtoken" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		ar, err := decodeAuthorizationResponse(ctx)
		assert.Nil(t, err)
		assert.NotNil(t, ar)
	})

	t.Run("Missed state", func(t *testing.T) {
		body := "id_token=v1&" +
			"&vp_token=t"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "state", err)
	})

	t.Run("Duplicated state", func(t *testing.T) {
		body := "id_token=v1&" +
			"vp_token=1&state=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "state", err)
	})

	t.Run("Error: interaction_details contains invalid data: base64", func(t *testing.T) {
		body := "vp_token=toke1&" +
			"&id_token=toke2" +
			"&interaction_details=   " +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		assert.ErrorContains(t, err, "base64 decode")
		requireOidc4VpError(t, "bad_request", "", "", "interaction_details", err)
	})

	t.Run("Error: interaction_details contains invalid data: json", func(t *testing.T) {
		body := "vp_token=toke1&" +
			"&id_token=toke2" +
			"&interaction_details=abcd" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		assert.ErrorContains(t, err, "json decode")
		requireOidc4VpError(t, "bad_request", "", "", "interaction_details", err)
	})

	t.Run("Error: authorization error response: missed error_description", func(t *testing.T) {
		body := "error=invalid_request" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "error_description", err)
	})

	t.Run("Error: authorization error response: duplicated error_description", func(t *testing.T) {
		body := "error=invalid_request" +
			"&error_description=unsupported%20client_id_scheme" +
			"&error_description=unsupported%20client_id_scheme" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "error_description", err)
	})

	t.Run("Missed id_token", func(t *testing.T) {
		body := "vp_token=v1&" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "id_token", err)
	})

	t.Run("Duplicated id_token", func(t *testing.T) {
		body := "vp_token=v1&" +
			"id_token=1&id_token=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "id_token", err)
	})

	t.Run("Missed vp_token", func(t *testing.T) {
		body := "id_token=v1&" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "vp_token", err)
	})

	t.Run("Duplicated vp_token", func(t *testing.T) {
		body := "id_token=v1&" +
			"vp_token=1&vp_token=2" +
			"&state=txid"

		ctx := createContextApplicationForm([]byte(body))

		_, err := decodeAuthorizationResponse(ctx)
		requireOidc4VpError(t, "bad_request", "", "", "vp_token", err)
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
	res := mapVerifyPresentationChecks(verifypresentation.PresentationVerificationResult{
		Checks: []*verifypresentation.Check{
			{
				Check: "check1",
				Error: errors.New("error1"),
			},
			{
				Check: "check2",
			},
		},
	}, &verifiable.Presentation{})

	assert.Len(t, res.Checks, 2)
	assert.EqualValues(t, "check1", res.Checks[0])
	assert.EqualValues(t, "check2", res.Checks[1])

	assert.Len(t, *res.Errors, 1)
	assert.EqualValues(t, "error1", (*res.Errors)[0])

	assert.False(t, res.Verified)
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

func requireOidc4VpError(t *testing.T, errCode string, component resterr.Component, failedOperation, incorrectValue string, actual error) { //nolint: unparam,lll
	var actualErr *oidc4vperr.Error
	assert.ErrorAs(t, actual, &actualErr)

	assert.Equal(t, errCode, actualErr.Code())
	assert.Equal(t, component, actualErr.ErrorComponent)
	assert.Equal(t, failedOperation, actualErr.Operation)
	assert.Equal(t, incorrectValue, actualErr.IncorrectValue)
	assert.Error(t, actualErr.Err)
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
			Tracer: nooptracer.NewTracerProvider().Tracer("")})

		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireOidc4VpError(t, "unauthorized", "", "", "", err)

		err = controller.RetrieveInteractionsClaim(c, "txid")
		requireOidc4VpError(t, "unauthorized", "", "", "", err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry,
			Tracer: nooptracer.NewTracerProvider().Tracer("")})

		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireOidc4VpError(t, "unauthorized", resterr.VerifierProfileSvcComponent, "", "", err)
	})
}

func TestController_InitiateOidcInteraction(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))

	oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
	oidc4VPSvc.EXPECT().InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).AnyTimes().Return(&oidc4vp.InteractionInfo{}, nil)

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
			Tracer:        nooptracer.NewTracerProvider().Tracer(""),
		})
		c := createContext(tenantID)
		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		assert.NoError(t, err)
	})

	t.Run("Profile not found", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Times(1).Return(nil, nil)

		controller := NewController(&Config{
			ProfileSvc:    mockProfileSvc,
			KMSRegistry:   kmsRegistry,
			OIDCVPService: oidc4VPSvc,
			Tracer:        nooptracer.NewTracerProvider().Tracer(""),
		})
		c := createContext(tenantID)
		err := controller.InitiateOidcInteraction(c, profileID, profileVersion)
		requireOidc4VpError(t, "unauthorized", resterr.VerifierProfileSvcComponent, "", "", err)
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
		gomock.Any(), gomock.Any(), gomock.Any(), []string{"test_scope"}, "", gomock.Any()).
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

		assert.Nil(t, err)
		assert.NotNil(t, result)
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
		assert.NoError(t, err)

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

		assert.Nil(t, err)
		assert.NotNil(t, result)
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
		assert.NoError(t, err)

		var pd2 presexch.PresentationDefinition

		err = json.Unmarshal([]byte(testPD), &pd2)
		assert.NoError(t, err)

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

		assert.Nil(t, err)
		assert.NotNil(t, result)
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
		assert.NoError(t, err)

		var pd2 presexch.PresentationDefinition

		err = json.Unmarshal([]byte(testPD), &pd2)
		assert.NoError(t, err)

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

		assert.Nil(t, result)

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "presentationDefinitionID", err)
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
		assert.NoError(t, err)

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

		assert.Nil(t, result)

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "presentationDefinitionFilters", err)
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

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "profile.OIDCConfig", err)
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

		requireOidc4VpError(t, "bad_request", resterr.VerifierOIDC4vpSvcComponent, "", "presentationDefinitionID", err)
	})

	t.Run("oidc4VPService.InitiateOidcInteraction failed", func(t *testing.T) {
		oidc4VPSvc := NewMockOIDC4VPService(gomock.NewController(t))
		oidc4VPSvc.EXPECT().
			InitiateOidcInteraction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
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

		requireOidc4VpError(t, "bad_request", "", "", "", err)
	})
}

func TestMatchField(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		_, matched, err := matchField(nil, "id")
		assert.NoError(t, err)
		assert.False(t, matched)
	})
}

func TestCopyPresentationDefinition(t *testing.T) {
	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd *presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		assert.NoError(t, err)

		copied, err := copyPresentationDefinition(pd)
		assert.NoError(t, err)
		assert.Equal(t, pd, copied)
	})
}

func TestApplyFieldsFilter(t *testing.T) {
	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		assert.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{"degree_type_id"})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 0)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Fail - field not found", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		assert.NoError(t, err)

		_, err = applyFieldsFilter(&pd, []string{"degree_type_id", "random_field"})
		assert.ErrorContains(t, err, "field random_field not found")
	})

	t.Run("Success - empty string filter(accept fields with empty ID)", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{""})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - supply fields filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPDWithFieldIDs), &pd)
		assert.NoError(t, err)

		result, err := applyFieldsFilter(&pd, []string{"degree_type_id"})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 0)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test prefix filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		const testPrefix = "*_test_prefix"

		pd.InputDescriptors[0].Constraints.Fields[0].ID = testPrefix + "_first"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = testPrefix + "_second"

		result, err := applyFieldsFilter(&pd, []string{testPrefix})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Fail - test invalid regex", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		const testPrefix = `*[ ]\K(?<!\d )(?=(?: ?\d){8})(?!(?: ?\d){9})\d[ \d]+\d`

		pd.InputDescriptors[0].Constraints.Fields[0].ID = testPrefix + "_first"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = testPrefix + "_second"

		_, err = applyFieldsFilter(&pd, []string{testPrefix})
		assert.ErrorContains(t, err, "failed to compile regex")
	})

	t.Run("Success - test suffix filter", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		const testSuffix = "test_suffix_*"

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first" + testSuffix
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second" + testSuffix

		result, err := applyFieldsFilter(&pd, []string{testSuffix})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first_group_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second_group_addon_id"

		result, err := applyFieldsFilter(&pd, []string{"*group*"})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "first_group_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "second_group_addon_id"

		result, err := applyFieldsFilter(&pd, []string{"*group*"})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Success - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "prefix_first_group_a_suffix"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "prefix_second_group_b_suffix"

		result, err := applyFieldsFilter(&pd, []string{"prefix*group*suffix"})
		assert.NoError(t, err)

		assert.Len(t, result.InputDescriptors[0].Constraints.Fields, 1)
		assert.Len(t, result.InputDescriptors[1].Constraints.Fields, 1)
	})

	t.Run("Error - test wildcard", func(t *testing.T) {
		var pd presexch.PresentationDefinition

		err := json.Unmarshal([]byte(testPD), &pd)
		assert.NoError(t, err)

		pd.InputDescriptors[0].Constraints.Fields[0].ID = "prefix_id"
		pd.InputDescriptors[1].Constraints.Fields[0].ID = "suffix_id"

		const invalidRegex = "^(#[=+[.rst:)$*"

		result, err := applyFieldsFilter(&pd, []string{invalidRegex})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to compile regex")
	})
}

func TestAddDynamicPresentation(t *testing.T) {
	t.Run("add dynamic success", func(t *testing.T) {
		resp, err := findPresentationDefinition(
			&profileapi.Verifier{
				OIDCConfig: &profileapi.OIDC4VPConfig{
					DynamicPresentationSupported: true,
				},
			},
			"someID",
			&InitiateOIDC4VPData{
				DynamicPresentationFilters: &PresentationDynamicFilters{
					Context: lo.ToPtr([]string{"a", "b"}),
					Type:    lo.ToPtr("someType"),
				},
				PresentationDefinitionFilters: &PresentationDefinitionFilters{
					Fields: lo.ToPtr([]string{"query_by_example"}),
				},
			},
		)

		assert.NotNil(t, resp)
		assert.NoError(t, err)

		assert.Equal(t, "someID", resp.ID)
		assert.Len(t, resp.InputDescriptors, 1)

		assert.EqualValues(t, "dynamic-0", resp.InputDescriptors[0].ID)

		assert.Len(t, resp.InputDescriptors[0].Constraints.Fields, 2)

		fields := resp.InputDescriptors[0].Constraints.Fields

		assert.EqualValues(t, "query_by_example", fields[0].ID)
		assert.EqualValues(t, []string{"$['@context']"}, fields[0].Path)
		assert.Len(t, fields[0].Filter.AllOf, 2)

		assert.EqualValues(t, "a", fields[0].Filter.AllOf[0].Contains["const"])
		assert.EqualValues(t, "b", fields[0].Filter.AllOf[1].Contains["const"])

		assert.EqualValues(t, "filter_type", fields[1].ID)
		assert.EqualValues(t, []string{"$['type']"}, fields[1].Path)
		assert.Len(t, fields[1].Filter.AllOf, 1)
		assert.EqualValues(t, "someType", fields[1].Filter.AllOf[0].Contains["const"])
	})

	t.Run("no fields success", func(t *testing.T) {
		resp, err := findPresentationDefinition(
			&profileapi.Verifier{
				OIDCConfig: &profileapi.OIDC4VPConfig{
					DynamicPresentationSupported: true,
				},
			},
			"someID",
			&InitiateOIDC4VPData{
				DynamicPresentationFilters: &PresentationDynamicFilters{
					Context: lo.ToPtr([]string{"a", "b"}),
					Type:    lo.ToPtr("someType"),
				},
				PresentationDefinitionFilters: &PresentationDefinitionFilters{},
			},
		)

		assert.NotNil(t, resp)
		assert.NoError(t, err)

		assert.Equal(t, "someID", resp.ID)
		assert.Len(t, resp.InputDescriptors, 1)

		assert.EqualValues(t, "dynamic-0", resp.InputDescriptors[0].ID)

		assert.Len(t, resp.InputDescriptors[0].Constraints.Fields, 2)

		fields := resp.InputDescriptors[0].Constraints.Fields

		assert.EqualValues(t, "dynamic_id", fields[0].ID)
		assert.EqualValues(t, []string{"$['@context']"}, fields[0].Path)
		assert.Len(t, fields[0].Filter.AllOf, 2)

		assert.EqualValues(t, "a", fields[0].Filter.AllOf[0].Contains["const"])
		assert.EqualValues(t, "b", fields[0].Filter.AllOf[1].Contains["const"])

		assert.EqualValues(t, "filter_type", fields[1].ID)
		assert.EqualValues(t, []string{"$['type']"}, fields[1].Path)
		assert.Len(t, fields[1].Filter.AllOf, 1)
		assert.EqualValues(t, "someType", fields[1].Filter.AllOf[0].Contains["const"])
	})

	t.Run("err no missing dynamic", func(t *testing.T) {
		resp, err := findPresentationDefinition(
			&profileapi.Verifier{
				OIDCConfig: &profileapi.OIDC4VPConfig{
					DynamicPresentationSupported: true,
				},
			},
			"someID",
			&InitiateOIDC4VPData{
				PresentationDefinitionFilters: &PresentationDefinitionFilters{},
			},
		)

		assert.Nil(t, resp)
		assert.ErrorContains(t, err,
			"dynamic presentation filters should be specified for dynamic presentation")
	})
}

func TestValidateVPTokenCWT(t *testing.T) {
	c := NewController(&Config{})

	_, err := c.validateVPTokenCWT(&verifiable.Presentation{})
	assert.ErrorContains(t, err, "cwt presentation is missed")

	_, err = c.validateVPTokenCWT(&verifiable.Presentation{
		CWT: &verifiable.VpCWT{},
	})
	assert.ErrorContains(t, err, "cwt vp map is empty")

	_, err = c.validateVPTokenCWT(&verifiable.Presentation{
		CWT: &verifiable.VpCWT{
			VPMap: map[string]interface{}{
				"ab": "b",
			},
		},
	})
	assert.ErrorContains(t, err, "cwt message is missed")
}

type idTokenClaimsID1 struct {
	CustomScopeClaims map[string]oidc4vp.Claims `json:"_scope,omitempty"`
	VPToken           idTokenVPToken            `json:"_vp_token"`
	AttestationVP     string                    `json:"_attestation_vp"`
	Nonce             string                    `json:"nonce"`
	Aud               string                    `json:"aud"`
	Exp               int64                     `json:"exp"`
}

type idTokenVPToken struct {
	PresentationSubmission map[string]interface{} `json:"presentation_submission"`
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
