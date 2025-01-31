/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc6749

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

// rfc6749ErrorCode is defined by spec: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type rfc6749ErrorCode string

const (
	// invalidRequest - the request is missing a required parameter,
	// includes an unsupported parameter value (other than grant type),
	// repeats a parameter, includes multiple credentials,
	// utilizes more than one mechanism for authenticating the client, or is otherwise malformed.
	//
	// In case of Access Token Request (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
	// the following additional clarifications are provided:
	//
	// The Authorization Server does not expect a Transaction Code in the
	// Pre-Authorized Code Flow but the Client provides a Transaction Code.
	//
	// The Authorization Server expects a Transaction Code in the Pre-Authorized Code Flow
	// but the Client does not provide a Transaction Code.
	invalidRequest rfc6749ErrorCode = "invalid_request"

	// invalidClient - Client authentication included, or unsupported authentication method.
	// The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate
	// which HTTP authentication schemes are supported.
	// If the client attempted to authenticate via the "Authorization" request header field,
	// the authorization server MUST respond with an HTTP 401 (Unauthorized) status code
	// and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.
	//
	// In case of Access Token Request (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
	// the following additional clarifications are provided:
	//
	// The Client tried to send a Token Request with a Pre-Authorized Code
	// without a Client ID but the Authorization Server does not support anonymous access.
	invalidClient rfc6749ErrorCode = "invalid_client"

	// invalidGrant - the provided authorization grant (e.g., authorization code, resource owner credentials)
	// or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request,
	// or was issued to another client.
	//
	// In case of Access Token Request (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
	// the following additional clarifications are provided:
	//
	// The Authorization Server expects a Transaction Code in the Pre-Authorized Code Flow
	// but the Client provides the wrong Transaction Code.
	//
	// The End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired.
	invalidGrant rfc6749ErrorCode = "invalid_grant"

	// unauthorizedClient - the authenticated client is not authorized to use this authorization grant type.
	unauthorizedClient rfc6749ErrorCode = "unauthorized_client"

	// unsupportedGrantType - the authorization grant type is not supported by the authorization server.
	unsupportedGrantType rfc6749ErrorCode = "unsupported_grant_type"

	// invalidScope The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
	invalidScope rfc6749ErrorCode = "invalid_scope"
)

// Error represents RFC6749 error.
type Error = resterr.RFCError[rfc6749ErrorCode]

func NewInvalidRequestError(err error) *Error {
	return &Error{
		ErrorCode:  invalidRequest,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidClientError(err error) *Error {
	return &Error{
		ErrorCode:  invalidClient,
		Err:        err,
		HTTPStatus: http.StatusUnauthorized,
	}
}

func NewInvalidGrantError(err error) *Error {
	return &Error{
		ErrorCode:  invalidGrant,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewUnauthorizedClientError(err error) *Error {
	return &Error{
		ErrorCode:  unauthorizedClient,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewUnsupportedGrantTypeError(err error) *Error {
	return &Error{
		ErrorCode:  unsupportedGrantType,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidScopeError(err error) *Error {
	return &Error{
		ErrorCode:  invalidScope,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func Parse(reader io.Reader) *Error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return NewInvalidRequestError(fmt.Errorf("read RFC6749Error: %w", err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	var e *Error

	if err = json.Unmarshal(b, &e); err != nil {
		return NewInvalidRequestError(fmt.Errorf("decode RFC6749Error from body: %s, err: %w", string(b), err)).
			WithHTTPStatusField(http.StatusInternalServerError)
	}

	return e
}
