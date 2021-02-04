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

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		op, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, op)

		require.Equal(t, 4, len(op.GetRESTHandlers()))
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("TODO - creates an authorization", func(t *testing.T) {
		op, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.CreateAuthorization(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("TODO - runs a comparison", func(t *testing.T) {
		op, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Compare(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func TestOperation_Extract(t *testing.T) {
	t.Run("TODO - performs an extraction", func(t *testing.T) {
		op, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Extract(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func TestOperation_Config(t *testing.T) {
	t.Run("TODO - get config", func(t *testing.T) {
		op, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Config(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}
