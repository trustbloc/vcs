/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"net/http"
)

func NewNotFoundError(err error) *Error {
	return &Error{
		ErrorCode:  notFound,
		Err:        err,
		HTTPStatus: http.StatusNotFound,
	}
}
