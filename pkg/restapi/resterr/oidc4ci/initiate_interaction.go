/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"net/http"
)

func NewUnauthorizedError(err error) *Error {
	return &Error{
		ErrorCode:  unauthorized,
		Err:        err,
		HTTPStatus: http.StatusUnauthorized,
	}
}

func NewBadRequestError(err error) *Error {
	return &Error{
		ErrorCode:  badRequest,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}
