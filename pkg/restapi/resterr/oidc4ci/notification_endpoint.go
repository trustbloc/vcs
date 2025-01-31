/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"net/http"
)

func NewInvalidNotificationIDError(err error) *Error {
	return &Error{
		ErrorCode:  invalidNotificationID,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewExpiredAckIDError(err error) *Error {
	return &Error{
		ErrorCode:  expiredAckID,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidNotificationRequestError(err error) *Error {
	return &Error{
		ErrorCode:  invalidNotificationRequest,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}
