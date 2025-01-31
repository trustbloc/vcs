/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc7591"
)

func TestHTTPErrorHandler(t *testing.T) {
	t.Run("Get echo.HTTPError", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(
			echo.NewHTTPError(http.StatusForbidden, "forbidden"), ctx)

		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, "{\"message\":\"forbidden\"}\n", rec.Body.String())
	})

	t.Run("Get oidc4cierr", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(
			oidc4cierr.NewForbiddenError(errors.New("unauthorized")).UsePublicAPIResponse(), ctx)

		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, "{\"error\":\"forbidden\","+
			"\"error_description\":\"forbidden[http status: 403]: unauthorized\"}\n", rec.Body.String())
	})

	t.Run("Get oidc4vperr", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(
			oidc4vperr.NewBadRequestError(errors.New("unauthorized")).
				WithErrorPrefix("with err prefix").
				WithOperation("with operation").
				WithComponent("with component").
				UsePublicAPIResponse(), ctx)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "{\"error\":\"bad_request\","+
			"\"error_description\":\"bad_request[component: with component; operation: with operation; "+
			"http status: 400]: with err prefix: unauthorized\"}\n", rec.Body.String())
	})

	t.Run("Get rfc6749", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)
		err := rfc6749.NewInvalidRequestError(errors.New("unauthorized"))

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(err, ctx)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "{\"error\":\"invalid_request\","+
			"\"http_status\":400,\""+
			"error_description\":\"unauthorized\"}\n", rec.Body.String())
	})

	t.Run("Get rfc7591Error", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(
			rfc7591.NewInvalidClientMetadataError(errors.New("unauthorized")).
				WithErrorPrefix("with err prefix").
				WithOperation("with operation").
				WithComponent("with component"), ctx)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "{\"error\":\"invalid_client_metadata\","+
			"\"component\":\"with component\","+
			"\"operation\":\"with operation\","+
			"\"http_status\":400,"+
			"\"error_description\":\"with err prefix: unauthorized\""+
			"}\n", rec.Body.String())
	})

	t.Run("Get generic error", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(errors.New("some error"), ctx)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Equal(t, "{\"error\":\"generic-error\","+
			"\"error_description\":\"some error\"}\n", rec.Body.String())
	})

	t.Run("Head", func(t *testing.T) {
		ctx, rec := createContext(http.MethodHead)

		HTTPErrorHandler(nooptracer.NewTracerProvider().Tracer(""))(errors.New("test"), ctx)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("Fosite", func(t *testing.T) {
		ctx, rec := createContext(http.MethodGet)

		err := resterr.NewFositeError(resterr.FositeIntrospectionError, ctx, &fositeErrorWriter{}, errors.New("some error"))

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

type fositeErrorWriter struct {
}

func (fef *fositeErrorWriter) WriteIntrospectionError(_ context.Context, rw http.ResponseWriter, _ error) {
	rw.WriteHeader(http.StatusInternalServerError)
}

func (fef *fositeErrorWriter) WriteAuthorizeError(
	_ context.Context, _ http.ResponseWriter, _ fosite.AuthorizeRequester, _ error) {
}

func (fef *fositeErrorWriter) WriteAccessError(
	_ context.Context, _ http.ResponseWriter, _ fosite.AccessRequester, _ error) {
}

func (fef *fositeErrorWriter) WritePushedAuthorizeError(
	_ context.Context, _ http.ResponseWriter, _ fosite.AuthorizeRequester, _ error) {
}
