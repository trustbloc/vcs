/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	did2 "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/issuer"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
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
		req.Header.Set("Authorization", "Bearer "+orgID)
	}

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestController_accessProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			&issuer.Profile{ID: "profValidID", OrganizationID: "testOrgID"},
			&issuer.SigningDID{},
			nil,
		)

		controller := NewController(mockProfileSvc, nil)

		_, _, err := controller.accessProfile("profValidID", "testOrgID")
		require.NoError(t, err)
	})

	t.Run("Profile with given id doesn't exist", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profInValidID").AnyTimes().Return(
			nil,
			nil,
			issuer.ErrDataNotFound,
		)

		controller := NewController(mockProfileSvc, nil)

		_, _, err := controller.accessProfile("profInValidID", "testOrgID")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})

	t.Run("Not visible for other organizations", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			&issuer.Profile{ID: "profValidID", OrganizationID: "testOrgID"},
			&issuer.SigningDID{},
			nil,
		)

		controller := NewController(mockProfileSvc, nil)

		_, _, err := controller.accessProfile("profValidID", "testAnotherID")
		requireValidationError(t, resterr.DoesntExist, "profile", err)
	})

	t.Run("get profile system error", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profValidID").AnyTimes().Return(
			nil, nil, errors.New("some other error"),
		)

		controller := NewController(mockProfileSvc, nil)

		_, _, err := controller.accessProfile("profValidID", "testOrgID")
		requireSystemError(t, "issuer.ProfileService", "GetProfile", err)
	})
}

func TestController_validateKMSConfig(t *testing.T) {
	t.Run("Success (use defult config)", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.validateKMSConfig(nil)
		require.NoError(t, err)
	})

	t.Run("Success(type aws)", func(t *testing.T) {
		controller := NewController(nil, nil)

		config := &KMSConfig{
			Endpoint: strPtr("aws://url"),
			Type:     "aws",
		}

		_, err := controller.validateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed endpoint (type aws)", func(t *testing.T) {
		controller := NewController(nil, nil)

		config := &KMSConfig{
			Type: "aws",
		}

		_, err := controller.validateKMSConfig(config)
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.endpoint", err)
	})

	t.Run("Success(type web)", func(t *testing.T) {
		controller := NewController(nil, nil)

		config := &KMSConfig{
			Endpoint: strPtr("aws://url"),
			Type:     "web",
		}

		_, err := controller.validateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed endpoint (type web)", func(t *testing.T) {
		controller := NewController(nil, nil)

		config := &KMSConfig{
			Type: "web",
		}

		_, err := controller.validateKMSConfig(config)
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.endpoint", err)
	})

	t.Run("Success(type local)", func(t *testing.T) {
		controller := NewController(nil, nil)

		config := &KMSConfig{
			DbPrefix:          strPtr("prefix"),
			DbType:            strPtr("type"),
			DbURL:             strPtr("url"),
			SecretLockKeyPath: strPtr("path"),
			Type:              "local",
		}

		_, err := controller.validateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed fields (type local)", func(t *testing.T) {
		controller := NewController(nil, nil)

		correct := &KMSConfig{
			DbPrefix:          strPtr("prefix"),
			DbType:            strPtr("type"),
			DbURL:             strPtr("url"),
			SecretLockKeyPath: strPtr("path"),
			Type:              "local",
		}

		incorrect := &KMSConfig{}

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbPrefix = nil
		_, err := controller.validateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbPrefix", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbURL = nil
		_, err = controller.validateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbURL", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbType = nil
		_, err = controller.validateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbType", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.SecretLockKeyPath = nil
		_, err = controller.validateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.secretLockKeyPath", err)
	})
}

func TestController_validateVCConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		controller := NewController(nil, nil)

		didMethods := []string{"orb", "web", "key"}

		for _, didMethod := range didMethods {
			contexts := []string{"test"}
			config := &VCConfig{
				Contexts:         &contexts,
				DidMethod:        VCConfigDidMethod(didMethod),
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
		controller := NewController(nil, nil)

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.Format = "incorrect"

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.format", err)
	})

	t.Run("Failed (incorrect signingAlgorithm)", func(t *testing.T) {
		controller := NewController(nil, nil)

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.SigningAlgorithm = "incorrect"

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.signingAlgorithm", err)
	})

	t.Run("Failed (incorrect keyType)", func(t *testing.T) {
		controller := NewController(nil, nil)

		incorrect := &VCConfig{}
		require.NoError(t, copier.Copy(incorrect, correct))

		incorrect.KeyType = strPtr("incorrect")

		_, err := controller.validateVCConfig(incorrect, ariesSupportedKeyTypes)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.keyType", err)
	})

	t.Run("Failed (incorrect didMethod)", func(t *testing.T) {
		controller := NewController(nil, nil)

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
		&issuer.SigningDID{},
		nil,
	)

	correctData := CreateIssuerProfileData{
		Name:           "Test",
		OidcConfig:     nil,
		OrganizationID: "testOrgId",
		Url:            "TestURL",
		KmsConfig: &KMSConfig{
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
		controller := NewController(mockProfileSvc, kmsRegistry)
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		require.NoError(t, err)
	})

	t.Run("Incorrect org id", func(t *testing.T) {
		controller := NewController(mockProfileSvc, kmsRegistry)
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.OrganizationID = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "organizationID", err)
	})

	t.Run("Incorrect kmsConfig Type", func(t *testing.T) {
		controller := NewController(mockProfileSvc, kmsRegistry)
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.KmsConfig.Type = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.type", err)
	})

	t.Run("Incorrect VcConfig SigningAlgorithm", func(t *testing.T) {
		controller := NewController(mockProfileSvc, kmsRegistry)
		body := CreateIssuerProfileData{}

		require.NoError(t, copier.Copy(&body, &correctData))

		body.VcConfig.SigningAlgorithm = "incorrect"

		_, err := controller.validateCreateProfileData(&body, "testOrgId")
		requireValidationError(t, resterr.InvalidValue, "vcConfig.signingAlgorithm", err)
	})

	t.Run("Incorrect VcConfig SigningAlgorithm", func(t *testing.T) {
		brokenKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))
		brokenKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("broken"))

		controller := NewController(mockProfileSvc, brokenKMSRegistry)

		_, err := controller.validateCreateProfileData(&correctData, "testOrgId")
		requireSystemError(t, "kms.Registry", "GetKeyManager", err)
	})
}

func TestController_mapToKMSConfigType(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		controller := NewController(nil, nil)

		tpe, err := controller.mapToKMSConfigType(vcskms.AWS)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeAws, tpe)

		tpe, err = controller.mapToKMSConfigType(vcskms.Local)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeLocal, tpe)

		tpe, err = controller.mapToKMSConfigType(vcskms.Web)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeWeb, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.mapToKMSConfigType("incorrect")
		require.Error(t, err)
	})
}

func TestController_mapToVCFormat(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		controller := NewController(nil, nil)

		tpe, err := controller.mapToVCFormat(vc.JwtVC)
		require.NoError(t, err)
		require.Equal(t, JwtVc, tpe)

		tpe, err = controller.mapToVCFormat(vc.LdpVC)
		require.NoError(t, err)
		require.Equal(t, LdpVc, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.mapToVCFormat("incorrect")
		require.Error(t, err)
	})
}

func TestController_mapToDIDMethod(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		controller := NewController(nil, nil)

		tpe, err := controller.mapToDIDMethod(did2.KeyDIDMethod)
		require.NoError(t, err)
		require.Equal(t, VCConfigDidMethodKey, tpe)

		tpe, err = controller.mapToDIDMethod(did2.OrbDIDMethod)
		require.NoError(t, err)
		require.Equal(t, VCConfigDidMethodOrb, tpe)

		tpe, err = controller.mapToDIDMethod(did2.WebDIDMethod)
		require.NoError(t, err)
		require.Equal(t, VCConfigDidMethodWeb, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.mapToDIDMethod("incorrect")
		require.Error(t, err)
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
			Format:           "jwt_vc",
			SigningAlgorithm: "",
			KeyType:          "",
			DIDMethod:        "web",
			Status:           map[string]interface{}{},
			Context:          nil,
		},
		OrganizationID: "orgID1",
		ID:             "testId",
	}

	signingDID := &issuer.SigningDID{
		DID:            "DID",
		UpdateKeyURL:   "key",
		RecoveryKeyURL: "key",
	}

	t.Run("Success", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.mapToIssuerProfile(correctProfile, signingDID)
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		controller := NewController(nil, nil)

		_, err := controller.mapToDIDMethod("incorrect")
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
		KmsConfig: &KMSConfig{
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
				Format:           "jwt_vc",
				SigningAlgorithm: "",
				KeyType:          "",
				DIDMethod:        "web",
				Status:           map[string]interface{}{},
				Context:          nil,
			}},
			&issuer.SigningDID{},
			nil)

		controller := NewController(mockProfileSvc, kmsRegistry)

		_, err := controller.createProfile(c, &correctData)
		require.NoError(t, err)
	})

	t.Run("validateCreateProfileData failed", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		controller := NewController(mockProfileSvc, kmsRegistry)

		incorrectData := CreateIssuerProfileData{}
		require.NoError(t, copier.Copy(&incorrectData, &correctData))

		incorrectData.VcConfig.DidMethod = "incorrect"

		_, err := controller.createProfile(c, &incorrectData)
		requireValidationError(t, resterr.InvalidValue, "vcConfig.didMethod", err)
	})

	t.Run("validateCredentialManifests failed", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))

		controller := NewController(mockProfileSvc, kmsRegistry)

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
			nil, nil, issuer.ErrProfileNameDuplication)

		controller := NewController(mockProfileSvc, kmsRegistry)

		_, err := controller.createProfile(c, &correctData)
		requireValidationError(t, resterr.AlreadyExist, "name", err)
	})

	t.Run("Create failed with other error", func(t *testing.T) {
		c := createContext("testOrgId")

		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return(
			nil, nil, errors.New("other error"))

		controller := NewController(mockProfileSvc, kmsRegistry)

		_, err := controller.createProfile(c, &correctData)
		requireSystemError(t, "issuer.ProfileService", "CreateProfile", err)
	})
}

func TestController_UpdateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").MinTimes(1).
			Return(&issuer.Profile{VCConfig: &issuer.VCConfig{
				Format:           "jwt_vc",
				SigningAlgorithm: "",
				KeyType:          "",
				DIDMethod:        "web",
				Status:           map[string]interface{}{},
				Context:          nil,
			}, OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(nil)

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

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
			}, OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(errors.New("error"))

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.PutIssuerProfilesProfileID(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "UpdateProfile", err)
	})
}

func TestController_DeleteProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().Delete(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().Delete(issuer.ProfileID("testId")).Times(1).Return(errors.New("error"))

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "DeleteProfile", err)
	})
}

func TestController_ActivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().ActivateProfile(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().ActivateProfile(issuer.ProfileID("testId")).Times(1).Return(errors.New("error"))

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.PostIssuerProfilesProfileIDActivate(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "ActivateProfile", err)
	})
}

func TestController_DeactivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().DeactivateProfile(issuer.ProfileID("testId")).Times(1).Return(nil)

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("testId").Times(1).
			Return(&issuer.Profile{OrganizationID: "orgID1", ID: "testId"}, &issuer.SigningDID{}, nil)
		mockProfileSvc.EXPECT().DeactivateProfile(issuer.ProfileID("testId")).Times(1).Return(errors.New("error"))

		controller := NewController(mockProfileSvc, nil)

		c := createContext("orgID1")

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		requireSystemError(t, "issuer.ProfileService", "DeactivateProfile", err)
	})
}

func TestController_AuthFailed(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return(ariesSupportedKeyTypes)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	mockProfileSvc := NewMockProfileService(gomock.NewController(t))
	mockProfileSvc.EXPECT().GetProfile("testId").AnyTimes().
		Return(&issuer.Profile{OrganizationID: "orgID1"}, &issuer.SigningDID{}, nil)

	t.Run("No token", func(t *testing.T) {
		c := createContext("")

		controller := NewController(mockProfileSvc, kmsRegistry)

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

		err = controller.PostIssuerProfilesProfileIDDeactivate(c, "testId")
		requireAuthError(t, err)
	})

	t.Run("Invlaid org id", func(t *testing.T) {
		c := createContext("orgID2")

		controller := NewController(mockProfileSvc, kmsRegistry)

		err := controller.DeleteIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.GetIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PutIssuerProfilesProfileID(c, "testId")
		requireValidationError(t, resterr.DoesntExist, "profile", err)

		err = controller.PostIssuerProfilesProfileIDActivate(c, "testId")
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
