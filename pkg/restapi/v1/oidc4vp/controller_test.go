/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4vp_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vp"
)

func TestController_OidcPresent(t *testing.T) {
	mockHTTPClient := NewMockHTTPClient(gomock.NewController(t))

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{StatusCode: http.StatusOK,
					Body: io.NopCloser(bytes.NewBuffer(nil))}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "fail to present",
			setup: func() {
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{StatusCode: http.StatusInternalServerError,
					Body: io.NopCloser(bytes.NewBuffer([]byte("error check id token")))}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "error check id token")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4vp.NewController(&oidc4vp.Config{
				DefaultHTTPClient: mockHTTPClient,
				Tracer:            trace.NewNoopTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.PresentAuthorizationResponse(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}
