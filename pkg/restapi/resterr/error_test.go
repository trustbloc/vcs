/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewUnauthorizedError(t *testing.T) {
	err := NewUnauthorizedError(errors.New("unauthorized"))
	require.Equal(t, "unauthorized: unauthorized", err.Error())

	httpCode, resp := err.HTTPCodeMsg()

	require.Equal(t, http.StatusUnauthorized, httpCode)
	requireCode(t, resp, Unauthorized.Name())
	requireMessage(t, resp, "unauthorized")
}

func TestNewSystemError(t *testing.T) {
	err := NewSystemError("testComp", "TestOp", errors.New("some error"))
	require.Equal(t, "system-error[testComp, TestOp]: some error", err.Error())

	httpCode, resp := err.HTTPCodeMsg()

	require.Equal(t, http.StatusInternalServerError, httpCode)
	requireCode(t, resp, SystemError.Name())
	requireMessage(t, resp, "some error")
}

func TestNewValidationError(t *testing.T) {
	t.Run("invalid value error", func(t *testing.T) {
		err := NewValidationError(InvalidValue, "test.value1", errors.New("some error"))
		require.Equal(t, "invalid-value[test.value1]: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusBadRequest, httpCode)
		requireCode(t, resp, InvalidValue.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("already exist error", func(t *testing.T) {
		err := NewValidationError(AlreadyExist, "test.value1", errors.New("some error"))
		require.Equal(t, "already-exist[test.value1]: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusConflict, httpCode)
		requireCode(t, resp, AlreadyExist.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("doesn't exist error", func(t *testing.T) {
		err := NewValidationError(DoesntExist, "test.value1", errors.New("some error"))
		require.Equal(t, "doesnt-exist[test.value1]: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusNotFound, httpCode)
		requireCode(t, resp, DoesntExist.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("bad request", func(t *testing.T) {
		err := NewValidationError(BadRequest, "test.value1", errors.New("some error"))
		require.Equal(t, "bad-request[test.value1]: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusBadRequest, httpCode)
		requireCode(t, resp, BadRequest.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("Condition not met error", func(t *testing.T) {
		err := NewValidationError(ConditionNotMet, "test.value1", errors.New("some error"))
		require.Equal(t, "condition-not-met[test.value1]: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusPreconditionFailed, httpCode)
		requireCode(t, resp, ConditionNotMet.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("profile not found error", func(t *testing.T) {
		err := NewCustomError(ProfileNotFound, errors.New("some error"))
		require.Equal(t, "profile-not-found: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusNotFound, httpCode)
		requireCode(t, resp, ProfileNotFound.Name())
		requireMessage(t, resp, "some error")
	})

	t.Run("action not allowed", func(t *testing.T) {
		err := NewCustomError(Forbidden, errors.New("some error"))
		require.Equal(t, "forbidden: some error", err.Error())

		httpCode, resp := err.HTTPCodeMsg()

		require.Equal(t, http.StatusForbidden, httpCode)
		requireCode(t, resp, Forbidden.Name())
		requireMessage(t, resp, "some error")
	})
}

func TestGetErrorDetails(t *testing.T) {
	t.Run("custom error", func(t *testing.T) {
		e := errors.New("some error")

		err := fmt.Errorf("got error: %w",
			NewSystemError(TransactionStoreComponent, "getData", e))

		errMsg, errCode, errComponent := GetErrorDetails(err)
		require.Equal(t, e.Error(), errMsg)
		require.Equal(t, string(SystemError), errCode)
		require.Equal(t, TransactionStoreComponent, errComponent)
	})

	t.Run("other error", func(t *testing.T) {
		err := errors.New("some error")

		errMsg, errCode, errComponent := GetErrorDetails(err)
		require.Equal(t, err.Error(), errMsg)
		require.Empty(t, errCode)
		require.Empty(t, errComponent)
	})
}
