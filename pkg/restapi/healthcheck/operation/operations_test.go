/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRESTHandlers(t *testing.T) {
	c := New()
	require.Equal(t, 1, len(c.GetRESTHandlers()))
}

func TestHealthCheck(t *testing.T) {
	c := New()

	b := &httptest.ResponseRecorder{}
	c.healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}
