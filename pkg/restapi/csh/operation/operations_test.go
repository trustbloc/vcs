/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
)

func TestNew(t *testing.T) {
	t.Run("returns an instance", func(t *testing.T) {
		o, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, o)
	})
}

func TestOperation_GetRESTHandlers(t *testing.T) {
	o := newOp(t)
	require.True(t, len(o.GetRESTHandlers()) > 0)
}

func TestOperation_CreateProfile(t *testing.T) {
	t.Run("TODO - creates a profile", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateProfile(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_CreateQuery(t *testing.T) {
	t.Run("TODO - creates a query", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateQuery(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("TODO - creates an authorization", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateAuthorization(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("TODO - runs a comparison", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.Compare(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func TestOperation_Extract(t *testing.T) {
	t.Run("TODO - performs an extraction", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.Extract(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func newOp(t *testing.T) *operation.Operation {
	t.Helper()

	op, err := operation.New(nil)
	require.NoError(t, err)

	return op
}
