/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logapi_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/restapi/v1/logapi"
)

func TestController(t *testing.T) {
	mr := NewMockrouter(gomock.NewController(t))

	mr.EXPECT().POST("/loglevels", gomock.Any()).Return(nil)
	assert.NotNil(t, logapi.NewController(mr))
}

func TestPostLogLevels(t *testing.T) {
	t.Run("changed log level", func(t *testing.T) {
		mr := NewMockrouter(gomock.NewController(t))
		mr.EXPECT().POST(gomock.Any(), gomock.Any()).AnyTimes()

		c := logapi.NewController(mr)

		body := newMockReader([]byte("DEBUG"))

		assert.NoError(t, c.PostLogLevels(echoContext(body)))
	})

	t.Run("invalid log level", func(t *testing.T) {
		mr := NewMockrouter(gomock.NewController(t))
		mr.EXPECT().POST(gomock.Any(), gomock.Any()).AnyTimes()

		c := logapi.NewController(mr)

		body := newMockReader([]byte("INVALID"))

		err := c.PostLogLevels(echoContext(body))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "logger: invalid log level")
	})

	t.Run("failed to read request", func(t *testing.T) {
		mr := NewMockrouter(gomock.NewController(t))
		mr.EXPECT().POST(gomock.Any(), gomock.Any()).AnyTimes()

		c := logapi.NewController(mr)

		err := c.PostLogLevels(echoContext(newMockReader([]byte("")).withError(fmt.Errorf("reader error"))))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read body: reader error")
	})
}

func echoContext(body io.Reader) echo.Context {
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMETextPlain)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

type mockReader struct {
	io.Reader
	err error
}

func newMockReader(value []byte) *mockReader {
	return &mockReader{Reader: bytes.NewBuffer(value)}
}

func (r *mockReader) withError(err error) *mockReader {
	r.err = err

	return r
}

func (r *mockReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	return r.Reader.Read(p)
}

func (r *mockReader) Close() error {
	return nil
}
