/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

// oidc4vpErrorCode is OIDC4VP-specific error codes, that are not declared in RFC specifications.
type oidc4vpErrorCode string

const (
	// unauthorized proprietary error code. Not described by any specification that VCS supports.
	unauthorized oidc4vpErrorCode = "unauthorized"

	// badRequest proprietary error code. Not described by any specification that VCS supports.
	badRequest oidc4vpErrorCode = "bad_request"

	// badRequest proprietary error code. Not described by any specification that VCS supports.
	expiredAckID oidc4vpErrorCode = "expired_ack_id"
)

// Error represents OIDC4CI error.
type Error = resterr.RFCError[oidc4vpErrorCode]

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

func NewExpiredAckIDError(err error) *Error {
	return &Error{
		ErrorCode:  expiredAckID,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func Parse(reader io.Reader) *Error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return NewBadRequestError(fmt.Errorf("read OIDC4VPErr: %w", err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	var e *Error

	if err = json.Unmarshal(b, &e); err != nil {
		return NewBadRequestError(fmt.Errorf("decode OIDC4VPErr from body: %s, err: %w", string(b), err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	return e
}
