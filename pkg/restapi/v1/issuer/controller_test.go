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
	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/issuer"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
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

func requireSystemError(t *testing.T, component, failedOperation string, actual error) { //nolint: unparam
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, resterr.SystemError, actualErr.Code)
	require.Equal(t, component, actualErr.Component)
	require.Equal(t, failedOperation, actualErr.FailedOperation)
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

func TestController_accessProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			&issuer.Profile{ID: "profValidID", OrganizationID: "testOrgID"},
			nil,
		)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		_, err := controller.accessProfile("profValidID", "testOrgID")
		require.NoError(t, err)
	})

	t.Run("Profile with given id doesn't exist", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profInValidID").AnyTimes().Return(
			nil,
			issuer.ErrDataNotFound,
		)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		_, err := controller.accessProfile("profInValidID", "testOrgID")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})

	t.Run("Not visible for other organizations", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			&issuer.Profile{ID: "profValidID", OrganizationID: "testOrgID"},
			nil,
		)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		_, err := controller.accessProfile("profValidID", "testAnotherID")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})

	t.Run("get profile system error", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			nil, errors.New("some other error"),
		)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		_, err := controller.accessProfile("profValidID", "testOrgID")
		requireSystemError(t, "issuer.ProfileService", "GetProfile", err)
	})
}

func TestController_validateVCConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{})

		didMethods := []string{"orb", "web", "key"}

		for _, didMethod := range didMethods {
			contexts := []string{"test"}
			config := &VCConfig{
				Contexts:         &contexts,
				DidMethod:        common.DIDMethod(didMethod),
				Format:           "jwt_vc",
				KeyType:          strPtr("ED25519"),
				SigningAlgorithm: "EdDSA",
				Status:           nil,
			}

			_, err := controller.validateVCConfig(config, ariesSupportedKeyTypes)
			require.NoError(t, err)
		}
	})

	correct := &VCConfig{
		Contexts:         nil,
		DidMethod:        "orb",
		Format:           "jwt_vc",
		KeyType:          strPtr("ED25519"),
		SigningAlgorithm: "EdDSA",
		Status:           nil,
	}

	t.Run("Failed (incorrect format)", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.Format = "incorrect"

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.format", err)
	})

	t.Run("Failed (incorrect signingAlgorithm)", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.SigningAlgorithm = "incorrect"

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.signingAlgorithm", err)
	})

	t.Run("Failed (incorrect keyType)", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.KeyType = strPtr("incorrect")

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.keyType", err)
	})

	t.Run("Failed (incorrect didMethod)", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.DidMethod = "incorrect"

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.didMethod", err)
	})
}

func TestController_validateCreateProfileData(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile("validID").AnyTimes().Return(
		&issuer.Profile{ID: "validID"},
		nil,
	)

	correctData := CreateIssuerProfileData{
		Name:           "Test",
		OidcConfig:     nil,
		OrganizationID: "testOrgId",
		Url:            "TestURL",
		KmsConfig: &common.KMSConfig{
			DbPrefix:          nil,
			DbType:            nil,
			DbURL:             nil,
			Endpoint:          strPtr("aws://url"),
			SecretLockKeyPath: nil,
			Type:              "aws",
		},
		VcConfig: VCConfig{
			Contexts:         nil,
			DidMethod:        "orb",
			Format:           "jwt_vc",
			KeyType:          strPtr("ED25519"),
			SigningAlgorithm: "EdDSA",
			Status:           nil,
		},
	}

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		require.NoError(t, err)
	})

	t.Run("Incorrect org id", func(t *testing.T) {
		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.OrganizationID = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "organizationID", err)
	})

	t.Run("Incorrect kmsConfig Type", func(t *testing.T) {
		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.KmsConfig.Type = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.type", err)
	})

	t.Run("Incorrect VcConfig SigningAlgorithm", func(t *testing.T) {
		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.VcConfig.SigningAlgorithm = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "vcConfig.signingAlgorithm", err)
	})

	t.Run("Incorrect VcConfig SigningAlgorithm", func(t *testing.T) {
		brokenKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		brokenKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("broken"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: brokenKMSRegistry})

		_, err := controller.validateCreateProfileData(&correctData, "testOrgId")
		requireSystemError(t, "kms.Registry", "GetKeyManager", err)
	})
}

func TestController_mapToIssuerProfile(t *testing.T) {
	correctProfile := &issuer.Profile{
		KMSConfig: &vcskms.Config{
			KMSType:           "aws",
			Endpoint:          "",
			SecretLockKeyPath: "",
			DBType:            "",
			DBURL:             "",
			DBPrefix:          "",
		},
		VCConfig: &issuer.VCConfig{
			Format:           vcsverifiable.Jwt,
			SigningAlgorithm: "",
			KeyType:          "",
			DIDMethod:        "web",
			Status:           map[string]interface{}{},
			Context:          nil,
		},
		OrganizationID: orgID,
		ID:             "testId",
		OIDCConfig:     map[string]interface{}{},
	}

	t.Run("Success", func(t *testing.T) {
		controller := NewController(&Config{})

		_, err := controller.mapToIssuerProfile(correctProfile)
		require.NoError(t, err)
	})

	t.Run("Incorrect oidc type", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrectProfile := &issuer.Profile{}
		require.NoError(t, copier.Copy(&incorrectProfile, &correctProfile))

		incorrectProfile.OIDCConfig = ""

		_, err := controller.mapToIssuerProfile(incorrectProfile)
		require.Error(t, err)
	})

	t.Run("Incorrect Status type", func(t *testing.T) {
		controller := NewController(&Config{})

		incorrectProfile := &issuer.Profile{}
		require.NoError(t, copier.Copy(&incorrectProfile, &correctProfile))

		incorrectProfile.VCConfig.Status = ""

		_, err := controller.mapToIssuerProfile(incorrectProfile)
		require.Error(t, err)
	})
}

func TestController_CreateProfile(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	correctData := CreateIssuerProfileData{
		Name:           "Test",
		OidcConfig:     nil,
		OrganizationID: "testOrgId",
		Url:            "TestURL",
		KmsConfig: &common.KMSConfig{
			DbPrefix:          nil,
			DbType:            nil,
			DbURL:             nil,
			Endpoint:          strPtr("aws://url"),
			SecretLockKeyPath: nil,
			Type:              "aws",
		},
		VcConfig: VCConfig{
			Contexts:         nil,
			DidMethod:        "orb",
			Format:           "jwt_vc",
			KeyType:          strPtr("ED25519"),
			SigningAlgorithm: "EdDSA",
			Status:           nil,
		},
	}

	t.Run("Success", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(
			&issuer.Profile{VCConfig: &issuer.VCConfig{
				Format:           vcsverifiable.Jwt,
				SigningAlgorithm: "",
				KeyType:          "",
				DIDMethod:        "web",
				Status:           map[string]interface{}{},
				Context:          nil,
			},
				SigningDID: &did.SigningDID{}},
			nil)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		_, err := controller.createProfile(c, &correctData)
		require.NoError(t, err)
	})

	t.Run("validateCreateProfileData failed", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		incorrectData := CreateIssuerProfileData{}
		require.NoError(t, copier.Copy(&incorrectData, &correctData))

		incorrectData.VcConfig.DidMethod = "incorrect"

		_, err := controller.createProfile(c, &incorrectData)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.didMethod", err)
	})

	t.Run("validateCredentialManifests failed", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		incorrectData := CreateIssuerProfileData{}
		require.NoError(t, copier.Copy(&incorrectData, &correctData))

		credentialManifests := []map[string]interface{}{{
			"invalid": "invalid",
		}}
		incorrectData.CredentialManifests = &credentialManifests

		_, err := controller.createProfile(c, &incorrectData)
		requireValidationError(t, resterr.InvalidValue, "credentialManifests", err)
	})

	t.Run("Name already exists", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(
			nil, issuer.ErrProfileNameDuplication)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		_, err := controller.createProfile(c, &correctData)
		requireValidationError(t, resterr.AlreadyExist, "name", err)
	})

	t.Run("Create failed with other error", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(
			nil, errors.New("other error"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		_, err := controller.createProfile(c, &correctData)
		requireSystemError(t, "issuer.ProfileService", "CreateProfile", err)
	})
}

func TestController_UpdateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").MinTimes(1).
			Return(&issuer.Profile{VCConfig: &issuer.VCConfig{
				Format:           vcsverifiable.Jwt,
				SigningAlgorithm: "",
				KeyType:          "",
				DIDMethod:        "web",
				Status:           map[string]interface{}{},
				Context:          nil,
			}, OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(nil)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PutIssuerProfilesProfileID(c, "testId")
		require.NoError(t, err)
	})

	t.Run("UpdateFailed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").MinTimes(1).
			Return(&issuer.Profile{VCConfig: &issuer.VCConfig{
				Format:           "ldp_vc",
				SigningAlgorithm: "",
				KeyType:          "",
				DIDMethod:        "web",
				Status:           map[string]interface{}{},
				Context:          nil,
			}, OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(errors.New("error"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PutIssuerProfilesProfileID(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "UpdateProfile", err)
	})
}

func TestController_DeleteProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().Delete(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().Delete(issuer.ProfileID("testId")).Times(1).Return(errors.New("error"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "DeleteProfile", err)
	})
}

func TestController_ActivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().ActivateProfile(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().ActivateProfile(issuer.ProfileID("testId")).Times(1).Return(errors.New("error"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "ActivateProfile", err)
	})
}

func TestController_DeactivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().DeactivateProfile(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: orgID, ID: "testId", SigningDID: &did.SigningDID{}}, nil)
		mockProfileSvc.EXPECT().DeactivateProfile("testId").Times(1).Return(errors.New("error"))

		controller := NewController(&Config{ProfileSvc: mockProfileSvc})

		c := createContext(orgID)

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "DeactivateProfile", err)
	})
}

func TestController_PostIssueCredentials(t *testing.T) {
	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockIssueCredsSvc := NewMockissueCredentialService(gomock.NewController(t))
	mockIssueCredsSvc.EXPECT().IssueCredential(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, nil)

	t.Run("Success JSON-LD", func(t *testing.T) {
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &issuer.VCConfig{
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
			Return(&issuer.Profile{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &issuer.VCConfig{
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
			Return(&issuer.Profile{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &issuer.VCConfig{
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
			Return(&issuer.Profile{
				OrganizationID: orgID,
				ID:             "testId",
				VCConfig: &issuer.VCConfig{
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
						Return(&issuer.Profile{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &issuer.VCConfig{
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
						Return(&issuer.Profile{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &issuer.VCConfig{
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
						Return(&issuer.Profile{
							OrganizationID: orgID,
							ID:             "testId",
							VCConfig: &issuer.VCConfig{
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
		Return(&issuer.Profile{OrganizationID: orgID, SigningDID: &did.SigningDID{}}, nil)

	t.Run("No token", func(t *testing.T) {
		c := createContext("")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.PostIssuerProfiles(c)
		requireAuthError(t, err)

		err = controller.DeleteIssuerProfilesProfileID(c, "testId")
		requireAuthError(t, err)

		err = controller.GetIssuerProfilesProfileID(c, "testId")
		requireAuthError(t, err)

		err = controller.PutIssuerProfilesProfileID(c, "testId")
		requireAuthError(t, err)

		err = controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		requireAuthError(t, err)

		err = controller.PostIssueCredentials(c, "testId")
		requireAuthError(t, err)

		err = controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		requireAuthError(t, err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

		controller := NewController(&Config{ProfileSvc: mockProfileSvc, KMSRegistry: kmsRegistry})

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.GetIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PutIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PostIssueCredentials(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})
}

/*
func TestController_DeleteIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.NewCreator()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController()

		err := controller.DeleteIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "code=401, message=missing authorization")
	})
}

func TestController_GetIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.NewCreator()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController()

		err := controller.GetIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "code=401, message=missing authorization")
	})
}

func TestController_PutIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.NewCreator()

		req := httptest.NewRequest(http.MethodPut, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController()

		err := controller.PutIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "code=401, message=missing authorization")
	})
}

func TestController_PostIssuerProfilesProfileIDActivate(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.NewCreator()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController()

		err := controller.PostIssuerProfilesProfileIDActivate(c, "profileID")
		require.EqualError(t, err, "code=401, message=missing authorization")
	})
}

func TestController_PostIssuerProfilesProfileIDDeactivate(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.NewCreator()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := NewController()

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "profileID")
		require.EqualError(t, err, "code=401, message=missing authorization")
	})
}
*/

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

func TestController_validateSignatureRepresentation(t *testing.T) {
	type args struct {
		getSignatureRepresentation func() *VCConfigSignatureRepresentation
	}
	tests := []struct {
		name    string
		args    args
		want    verifiable.SignatureRepresentation
		wantErr bool
	}{
		{
			name: "OK JWS",
			args: args{
				getSignatureRepresentation: func() *VCConfigSignatureRepresentation {
					jws := JWS
					return &jws
				},
			},
			want:    verifiable.SignatureJWS,
			wantErr: false,
		},
		{
			name: "OK ProofValue",
			args: args{
				getSignatureRepresentation: func() *VCConfigSignatureRepresentation {
					pw := ProofValue
					return &pw
				},
			},
			want:    verifiable.SignatureProofValue,
			wantErr: false,
		},
		{
			name: "Error Unsupported",
			args: args{
				getSignatureRepresentation: func() *VCConfigSignatureRepresentation {
					res := VCConfigSignatureRepresentation("")
					return &res
				},
			},
			want:    verifiable.SignatureProofValue,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{}
			got, err := c.validateSignatureRepresentation(tt.args.getSignatureRepresentation())
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSignatureRepresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("validateSignatureRepresentation() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_mapToSignatureRepresentation(t *testing.T) {
	type args struct {
		signatureRepresentation verifiable.SignatureRepresentation
	}
	tests := []struct {
		name    string
		args    args
		want    VCConfigSignatureRepresentation
		wantErr bool
	}{
		{
			name: "OK JWS",
			args: args{
				signatureRepresentation: verifiable.SignatureJWS,
			},
			want:    JWS,
			wantErr: false,
		},
		{
			name: "OK ProofValue",
			args: args{
				signatureRepresentation: verifiable.SignatureProofValue,
			},
			want:    ProofValue,
			wantErr: false,
		},
		{
			name: "Error unsupported",
			args: args{
				signatureRepresentation: 3,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{}
			got, err := c.mapToSignatureRepresentation(tt.args.signatureRepresentation)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapToSignatureRepresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mapToSignatureRepresentation() got = %v, want %v", got, tt.want)
			}
		})
	}
}
