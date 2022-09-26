/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mw_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/restapi/v1/mw"
)

func TestApiKeyAuth(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		handlerCalled := false
		handler := func(c echo.Context) error {
			handlerCalled = true
			return c.String(http.StatusOK, "test")
		}

		middlewareChain := mw.APIKeyAuth("test-api-key")(handler)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middlewareChain(c)

		require.NoError(t, err)
		require.True(t, handlerCalled)
	})

	t.Run("401 Unauthorized", func(t *testing.T) {
		handlerCalled := false
		handler := func(c echo.Context) error {
			handlerCalled = true
			return c.String(http.StatusOK, "test")
		}

		middlewareChain := mw.APIKeyAuth("test-api-key")(handler)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "invalid-api-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middlewareChain(c)

		require.Error(t, err)
		require.Contains(t, err.Error(), "Unauthorized")
		require.False(t, handlerCalled)
	})

	t.Run("skip health check endpoint", func(t *testing.T) {
		handlerCalled := false
		handler := func(c echo.Context) error {
			handlerCalled = true
			return c.String(http.StatusOK, "test")
		}

		middlewareChain := mw.APIKeyAuth("test-api-key")(handler)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middlewareChain(c)

		require.NoError(t, err)
		require.True(t, handlerCalled)
	})
}
