/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier_test

import (
	"bytes"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/restapi/v1/verifier"
	verifiersvc "github.com/trustbloc/vcs/pkg/verifier"
)

var (
	//go:embed testdata/create_profile_data.json
	createProfileData []byte
	//go:embed testdata/update_profile_data.json
	updateProfileData []byte
)

//nolint:gochecknoglobals
var (
	verificationChecks = &verifiersvc.VerificationChecks{
		Credential: &verifiersvc.CredentialChecks{
			Proof: true,
			Format: []vc.Format{
				vc.JwtVC,
				vc.LdpVC,
			},
			Status: true,
		},
		Presentation: &verifiersvc.PresentationChecks{
			Proof: true,
			Format: []verifiersvc.PresentationFormat{
				verifiersvc.JwtVP,
				verifiersvc.LdpVP,
			},
		},
	}

	testProfile = &verifiersvc.Profile{
		ID:             "id",
		Name:           "test profile",
		URL:            "https://test-verifier.com",
		Active:         true,
		OrganizationID: "orgID",
		Checks:         verificationChecks,
		OIDCConfig:     map[string]interface{}{"config": "value"},
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
		req.Header.Set("Authorization", "Bearer org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.GetVerifierProfiles(c)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetAllProfiles("org1").Times(1).Return(nil, errors.New("get all profiles error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer org1")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.GetVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get verifier profiles")
	})
}

func TestController_PostVerifierProfiles(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any()).Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfiles(c)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Create(gomock.Any()).Times(1).Return(nil, errors.New("create profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(createProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfiles(c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create verifier profile")
	})
}

func TestController_DeleteVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete("profileID").Times(1).Return(nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Delete("profileID").Times(1).Return(errors.New("delete profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.DeleteVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to delete verifier profile")
	})
}

func TestController_GetVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

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

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.GetVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), verifiersvc.ErrProfileNotFound.Error())
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().GetProfile("profileID").Times(1).Return(nil, errors.New("get profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.GetVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get verifier profile")
	})
}

func TestController_PutVerifierProfilesProfileID(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(testProfile, nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(updateProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PutVerifierProfilesProfileID(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().Update(gomock.Any()).Times(1).Return(nil, errors.New("update profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(updateProfileData))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PutVerifierProfilesProfileID(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update verifier profile")
	})
}

func TestController_PostVerifierProfilesProfileIDActivate(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().ActivateProfile("profileID").Times(1).Return(nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfilesProfileIDActivate(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().ActivateProfile("profileID").Times(1).Return(errors.New("activate profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfilesProfileIDActivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to activate verifier profile")
	})
}

func TestController_PostVerifierProfilesProfileIDDeactivate(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().DeactivateProfile("profileID").Times(1).Return(nil)

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfilesProfileIDDeactivate(c, "profileID")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error from profile service", func(t *testing.T) {
		mockProfileSvc := NewMockProfileService(gomock.NewController(t))
		mockProfileSvc.EXPECT().DeactivateProfile("profileID").Times(1).Return(errors.New("deactivate profile error"))

		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := verifier.NewController(mockProfileSvc)

		err := controller.PostVerifierProfilesProfileIDDeactivate(c, "profileID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deactivate verifier profile")
	})
}
