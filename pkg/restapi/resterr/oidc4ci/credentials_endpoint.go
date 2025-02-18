/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func NewInvalidCredentialRequestError(err error) *Error {
	return &Error{
		ErrorCode:  invalidCredentialRequest,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewUnsupportedCredentialTypeError(err error) *Error {
	return &Error{
		ErrorCode:  unsupportedCredentialType,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewUnsupportedCredentialFormatError(err error) *Error {
	return &Error{
		ErrorCode:  unsupportedCredentialFormat,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidProofError(err error) *Error {
	return &Error{
		ErrorCode:  invalidProof,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidEncryptionParametersError(err error) *Error {
	return &Error{
		ErrorCode:  invalidEncryptionParameters,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func ParseCredentialEndpointErrorResponse(reader io.Reader) *Error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return NewInvalidCredentialRequestError(
			fmt.Errorf("read OIDC4CI error: %w", err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	var e *Error

	if err = json.Unmarshal(b, &e); err != nil {
		return NewInvalidCredentialRequestError(
			fmt.Errorf("decode OIDC4CI error from body: %s, err: %w", string(b), err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	return e
}
