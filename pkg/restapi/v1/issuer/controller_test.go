/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

func TestController_PostIssuerProfiles(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.PostIssuerProfiles(c)
		require.EqualError(t, err, "not implemented")
	})
}

func TestController_DeleteIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.DeleteIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "not implemented")
	})
}

func TestController_GetIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.GetIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "not implemented")
	})
}

func TestController_PutIssuerProfilesProfileID(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodPut, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.PutIssuerProfilesProfileID(c, "profileID")
		require.EqualError(t, err, "not implemented")
	})
}

func TestController_PostIssuerProfilesProfileIDActivate(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.PostIssuerProfilesProfileIDActivate(c, "profileID")
		require.EqualError(t, err, "not implemented")
	})
}

func TestController_PostIssuerProfilesProfileIDDeactivate(t *testing.T) {
	t.Run("not implemented", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := issuer.NewController()

		err := controller.PostIssuerProfilesProfileIDDeactivate(c, "profileID")
		require.EqualError(t, err, "not implemented")
	})
}
