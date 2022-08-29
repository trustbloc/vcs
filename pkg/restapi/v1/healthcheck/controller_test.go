/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/restapi/v1/healthcheck"
)

func TestController_GetHealthcheck(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		controller := &healthcheck.Controller{}

		err := controller.GetHealthcheck(c)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}
