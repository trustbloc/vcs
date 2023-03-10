/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package version_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/restapi/v1/version"
)

func TestController(t *testing.T) {
	route := NewMockrouter(gomock.NewController(t))

	route.EXPECT().GET("/version", gomock.Any()).Return(nil)
	route.EXPECT().GET("/version/system", gomock.Any()).Return(nil)
	assert.NotNil(t, version.NewController(route, version.Config{}, nil))
}

func TestGetVersion(t *testing.T) {
	route := NewMockrouter(gomock.NewController(t))
	route.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()

	c := version.NewController(route, version.Config{
		Version:       "123",
		ServerVersion: "321",
	}, nil)

	ctx, recorder := echoContext()
	assert.NoError(t, c.Version(ctx))
	b, err := io.ReadAll(recorder.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"version":"123"}`, strings.ReplaceAll(string(b), "\n", ""))
}

func TestGetServerVersion(t *testing.T) {
	route := NewMockrouter(gomock.NewController(t))
	route.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()

	c := version.NewController(route, version.Config{
		Version:       "123",
		ServerVersion: "321",
	}, nil)

	ctx, recorder := echoContext()
	assert.NoError(t, c.ServerVersion(ctx))
	b, err := io.ReadAll(recorder.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"version":"321"}`, strings.ReplaceAll(string(b), "\n", ""))
}

func echoContext() (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()

	var body io.Reader = http.NoBody

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}
