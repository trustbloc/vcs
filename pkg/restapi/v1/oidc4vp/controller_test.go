/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4vp_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

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
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer(nil)),
					}, nil,
				)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "fail to send request",
			setup: func() {
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(
					nil,
					errors.New("do request error"),
				)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "failed to send request")
			},
		},
		{
			name: "fail to read response body",
			setup: func() {
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(&failReader{}),
					}, nil,
				)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "failed to read response body")
			},
		},
		{
			name: "fail to present",
			setup: func() {
				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(bytes.NewBuffer([]byte("error check id token"))),
					}, nil,
				)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "error check id token")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4vp.NewController(&oidc4vp.Config{
				HTTPClient: mockHTTPClient,
				Tracer:     nooptracer.NewTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.PresentAuthorizationResponse(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

type failReader struct{}

func (f *failReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}
