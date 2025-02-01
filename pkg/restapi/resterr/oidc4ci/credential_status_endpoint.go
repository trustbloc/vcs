/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"net/http"
)

func NewForbiddenError(err error) *Error {
	return &Error{
		ErrorCode:  forbidden,
		Err:        err,
		HTTPStatus: http.StatusForbidden,
	}
}
