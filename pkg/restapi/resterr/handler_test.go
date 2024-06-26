/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	nooptracer "go.opentelemetry.io/otel/trace/noop"
)

func requireMessage(t *testing.T, resp interface{}, msg string) {
	m, ok := resp.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, msg, m["message"])
}

func requireCode(t *testing.T, resp interface{}, code string) {
	m, ok := resp.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, code, m["code"])
}

func TestHTTPErrorHandler_processError(t *testing.T) {
	t.Run("echo error", func(t *testing.T) {
		code, resp := processError(echo.NewHTTPError(http.StatusForbidden, "forbidden"))
		require.Equal(t, http.StatusForbidden, code)
		requireMessage(t, resp, "forbidden")
	})

	t.Run("echo internal error", func(t *testing.T) {
		err := echo.NewHTTPError(http.StatusForbidden, "forbidden")
		require.Error(t, err.SetInternal(echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")))

		code, resp := processError(err)
		require.Equal(t, http.StatusForbidden, code)
		requireMessage(t, resp, "code=403, message=forbidden, internal=code=401, message=unauthorized")
	})

	t.Run("rest error", func(t *testing.T) {
		code, resp := processError(NewUnauthorizedError(errors.New("unauthorized")))
		require.Equal(t, http.StatusUnauthorized, code)
		requireCode(t, resp, Unauthorized.Name())
		requireMessage(t, resp, "unauthorized")
	})

	t.Run("client registration error", func(t *testing.T) {
		code, resp := processError(&RegistrationError{
			Code: "invalid_client_metadata",
			Err:  fmt.Errorf("grant type implicit not supported"),
		})
		require.Equal(t, http.StatusBadRequest, code)

		m, ok := resp.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "grant type implicit not supported", m["error_description"])
	})

	t.Run("generic error", func(t *testing.T) {
		code, resp := processError(errors.New("generic error"))
		require.Equal(t, http.StatusInternalServerError, code)
		requireCode(t, resp, "generic-error")
		requireMessage(t, resp, "generic error")
	})
}

func TestHTTPErrorHandler(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(NewUnauthorizedError(errors.New("unauthorized")), ctx)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Equal(t, "{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}\n",
			rec.Body.String())
	})

	t.Run("Head", func(t *testing.T) {
		ctx, rec := createContext(http.MethodHead)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(errors.New("test"), ctx)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("Fosite", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))
		mockFositeErrWriter.EXPECT().WriteIntrospectionError(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Do(
			func(ctx context.Context, rw http.ResponseWriter, err error) {
				rw.WriteHeader(http.StatusInternalServerError)
			})
		err := NewFositeError(FositeIntrospectionError, ctx, mockFositeErrWriter, errors.New("some error"))

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(err, ctx)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func createContext(method string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()

	req := httptest.NewRequest(method, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}
