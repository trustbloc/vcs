/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc7591

import (
	"net/http"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

// rfc7591ErrorCode is defined by spec: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
type rfc7591ErrorCode string

const (
	// invalidRedirectURI - the value of one or more redirection URIs is invalid.
	invalidRedirectURI rfc7591ErrorCode = "invalid_redirect_uri"

	// invalidClientMetadata = the value of one of the client metadata fields is invalid
	// and the server has rejected this request.
	// Note that an authorization server MAY choose to substitute a valid value for any requested parameter
	// of a client's metadata.
	invalidClientMetadata rfc7591ErrorCode = "invalid_client_metadata"

	// invalidSoftwareStatement - the software statement presented is invalid.
	invalidSoftwareStatement rfc7591ErrorCode = "invalid_software_statement"

	// unapprovedSoftwareStatement - the software statement presented is not approved for use by this authorization server.
	unapprovedSoftwareStatement rfc7591ErrorCode = "unapproved_software_statement"
)

// Error represents RFC7591 error.
type Error = resterr.RFCError[rfc7591ErrorCode]

func NewInvalidRedirectURIError(err error) *Error {
	return &Error{
		ErrorCode:  invalidRedirectURI,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidClientMetadataError(err error) *Error {
	return &Error{
		ErrorCode:  invalidClientMetadata,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewInvalidSoftwareStatementError(err error) *Error {
	return &Error{
		ErrorCode:  invalidSoftwareStatement,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}

func NewUnapprovedSoftwareStatementError(err error) *Error {
	return &Error{
		ErrorCode:  unapprovedSoftwareStatement,
		Err:        err,
		HTTPStatus: http.StatusBadRequest,
	}
}
