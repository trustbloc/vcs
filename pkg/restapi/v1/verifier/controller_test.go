/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	verifiersvc "github.com/trustbloc/vcs/pkg/verifier"
)

const (
	orgID      = "orgID1"
	userHeader = "X-User"
)

var (
	//go:embed testdata/create_profile_data.json
	createProfileData []byte
	//go:embed testdata/update_profile_data.json
	updateProfileData []byte
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

//nolint:gochecknoglobals
var (
	verificationChecks = &verifiersvc.VerificationChecks{
		Credential: verifiersvc.CredentialChecks{
			Proof: true,
			Format: []vc.Format{
				vc.Jwt,
				vc.Ldp,
			},
			Status: true,
		},
		Presentation: &verifiersvc.PresentationChecks{
			Proof: true,
			Format: []vc.Format{
				vc.Jwt,
				vc.Ldp,
			},
		},
	}

	testProfile = &verifiersvc.Profile{
		ID:             "profileID",
		Name:           "test profile",
		URL:            "https://test-verifier.com",
		Active:         true,
		OrganizationID: "org1",
		Checks:         verificationChecks,
	}
)

func TestController_GetVerifierProfiles(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetAllProfiles("org1").Times(1).Return([]*verifiersvc.Profile{
			{
				ID:             "id1",
				Name:           "profile1",
				Active:         true,
				OrganizationID: "org1",
				Checks:         verificationChecks,
			},
			{
				ID:             "id2",
				Name:           "profile2",
				Active:         true,
				OrganizationID: "org1",
				Checks:         verificationChecks,
			},
		}, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfiles(c)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetAllProfiles("org1").Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetAllProfiles("org1").Times(1).Return(nil, errors.New("get all profiles error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get all profiles")
	})
}

func TestController_PostVerifierProfiles(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{
			ProfileSvc:  mockProfileSvc,
			KMSRegistry: kmsRegistry,
		})

		err := controller.PostVerifierProfiles(c)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("invalid org id", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "invalid")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "org id mismatch")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("create profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.PostVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create profile")
	})
}

func TestController_validateCreateVerifierProfileData(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	intFilterType := "integer"
	required := presexch.Required
	pd := &presexch.PresentationDefinition{
		ID:      "c1b88ce1-8460-4baf-8f16-4759a2f055fd",
		Purpose: "To sell you a drink we need to know that you are an adult.",
		InputDescriptors: []*presexch.InputDescriptor{{
			ID:      "age_descriptor",
			Purpose: "Your age should be greater or equal to 18.",
			Schema: []*presexch.Schema{{
				URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
			}},
			Constraints: &presexch.Constraints{
				LimitDisclosure: &required,
				Fields: []*presexch.Field{{
					Path:      []string{"$.age"},
					Predicate: &required,
					Filter: &presexch.Filter{
						Type:    &intFilterType,
						Minimum: 18,
					},
				}},
			},
		}},
	}

	pdBytes, err := json.Marshal(pd)
	require.NoError(t, err)

	pdInput := []PresentationDefinition{pdBytes}

	correct := &CreateVerifierProfileData{
		Checks: VerifierChecks{},
		KmsConfig: &common.KMSConfig{
			DbPrefix:          nil,
			DbType:            nil,
			DbURL:             nil,
			Endpoint:          strPtr("aws://url"),
			SecretLockKeyPath: nil,
			Type:              "aws",
		},
		Name: "Test",
		OidcConfig: &OIDC4VPConfig{
			DidMethod:          "orb",
			RoSigningAlgorithm: "EdDSA",
		},
		OrganizationID:          "test",
		PresentationDefinitions: &pdInput,
		Url:                     nil,
	}

	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		controller := NewController(&Config{
			ProfileSvc:  mockProfileSvc,
			KMSRegistry: kmsRegistry,
		})

		_, _, err := controller.validateCreateVerifierProfileData(correct)
		require.NoError(t, err)
	})

	t.Run("Invalid kms config", func(t *testing.T) {
		controller := NewController(&Config{
			KMSRegistry: kmsRegistry,
		})

		incorrect := &CreateVerifierProfileData{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.KmsConfig.Type = "incorrect"

		_, _, err := controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.type", err)
	})

	t.Run("Broken KMS Registry", func(t *testing.T) {
		brokenKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		brokenKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("broken"))

		controller := NewController(&Config{KMSRegistry: brokenKMSRegistry})

		_, _, err := controller.validateCreateVerifierProfileData(correct)
		requireSystemError(t, "kms.Registry", "GetKeyManager", err)
	})

	t.Run("Invalid checks", func(t *testing.T) {
		controller := NewController(&Config{
			KMSRegistry: kmsRegistry,
		})

		incorrect := &CreateVerifierProfileData{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.Checks.Credential.Format = []common.VCFormat{"invalid"}

		_, _, err := controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "checks.credential.format", err)

		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.Checks.Presentation = &PresentationChecks{
			Format: []common.VPFormat{"invalid"},
		}

		_, _, err = controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "checks.presentation.format", err)
	})

	t.Run("Invalid OIDC4VPConfig", func(t *testing.T) {
		controller := NewController(&Config{
			KMSRegistry: kmsRegistry,
		})

		incorrect := &CreateVerifierProfileData{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.OidcConfig.DidMethod = "test"

		_, _, err := controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "oidcConfig.didMethod", err)

		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.OidcConfig.RoSigningAlgorithm = "invalid"

		_, _, err = controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "oidcConfig.roSigningAlgorithm", err)
	})

	t.Run("Invalid PD", func(t *testing.T) {
		controller := NewController(&Config{
			KMSRegistry: kmsRegistry,
		})

		incorrect := &CreateVerifierProfileData{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrectPDInput := []PresentationDefinition{[]byte("invalid json")}
		incorrect.PresentationDefinitions = &incorrectPDInput

		_, _, err := controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "presentationDefinition", err)

		require.NoError(t, copier.Copy(incorrect, correct))

		incorrectPDInput = []PresentationDefinition{[]byte("{}")}
		incorrect.PresentationDefinitions = &incorrectPDInput

		_, _, err = controller.validateCreateVerifierProfileData(incorrect)
		requireValidationError(t, resterr.InvalidValue, "presentationDefinition", err)
	})
}

func TestController_DeleteVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete("profileID").Times(1).Return(nil)
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete(gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("block access to profiles of other organizations", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete(gomock.Any()).Times(0)
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org2")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile with given id profileID, doesn't exist")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete("profileID").Times(1).Return(errors.New("delete profile error"))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete profile")
	})
}

func TestController_GetVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfilesProfileID(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("404 Not Found", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(nil, verifiersvc.ErrProfileNotFound)

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile with given id profileID, doesn't exist")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(nil, errors.New("get profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.GetVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get profile")
	})
}

func TestController_PutVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(testProfile, nil)
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(updateProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PutVerifierProfilesProfileID(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(updateProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PutVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(nil, errors.New("update profile error"))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(updateProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PutVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "update profile")
	})
}

func TestController_PostVerifierProfilesProfileIDActivate(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().ActivateProfile("profileID").Times(1).Return(nil)
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDActivate(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().ActivateProfile(gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDActivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().ActivateProfile("profileID").Times(1).Return(errors.New("activate profile error"))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDActivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "activate profile")
	})
}

func TestController_PostVerifierProfilesProfileIDDeactivate(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().DeactivateProfile("profileID").Times(1).Return(nil)
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDDeactivate(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing authorization", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().DeactivateProfile(gomock.Any()).Times(0)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDDeactivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization")
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().DeactivateProfile("profileID").Times(1).Return(errors.New("deactivate profile error"))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(userHeader, "org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		err := controller.PostVerifierProfilesProfileIDDeactivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate profile")
	})
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
		Return(&verifiersvc.Profile{
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
		Return(&verifiersvc.Profile{
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

func strPtr(str string) *string {
	return &str
}

// nolint: unparam
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
