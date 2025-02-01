/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError(t *testing.T) {
	err := errors.New("some error")

	tests := []struct {
		name       string
		createFunc func(error) *Error
		want       *Error
	}{
		{
			name:       "OK NewForbiddenError",
			createFunc: NewForbiddenError,
			want: &Error{
				ErrorCode:  forbidden,
				Err:        err,
				HTTPStatus: http.StatusForbidden,
			},
		},
		{
			name:       "OK NewInvalidCredentialRequestError",
			createFunc: NewInvalidCredentialRequestError,
			want: &Error{
				ErrorCode:  invalidCredentialRequest,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewUnsupportedCredentialTypeError",
			createFunc: NewUnsupportedCredentialTypeError,
			want: &Error{
				ErrorCode:  unsupportedCredentialType,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewUnsupportedCredentialFormatError",
			createFunc: NewUnsupportedCredentialFormatError,
			want: &Error{
				ErrorCode:  unsupportedCredentialFormat,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidProofError",
			createFunc: NewInvalidProofError,
			want: &Error{
				ErrorCode:  invalidProof,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidEncryptionParametersError",
			createFunc: NewInvalidEncryptionParametersError,
			want: &Error{
				ErrorCode:  invalidEncryptionParameters,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewForbiddenError",
			createFunc: NewForbiddenError,
			want: &Error{
				ErrorCode:  forbidden,
				Err:        err,
				HTTPStatus: http.StatusForbidden,
			},
		},
		{
			name:       "OK NewUnauthorizedError",
			createFunc: NewUnauthorizedError,
			want: &Error{
				ErrorCode:  unauthorized,
				Err:        err,
				HTTPStatus: http.StatusUnauthorized,
			},
		},
		{
			name:       "OK NewBadRequestError",
			createFunc: NewBadRequestError,
			want: &Error{
				ErrorCode:  badRequest,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidNotificationIDError",
			createFunc: NewInvalidNotificationIDError,
			want: &Error{
				ErrorCode:  invalidNotificationID,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewExpiredAckIDError",
			createFunc: NewExpiredAckIDError,
			want: &Error{
				ErrorCode:  expiredAckID,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidNotificationRequestError",
			createFunc: NewInvalidNotificationRequestError,
			want: &Error{
				ErrorCode:  invalidNotificationRequest,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewNotFoundError",
			createFunc: NewNotFoundError,
			want: &Error{
				ErrorCode:  notFound,
				Err:        err,
				HTTPStatus: http.StatusNotFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.createFunc(err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRFCError_ParseCredentialEndpointErrorResponse(t *testing.T) {
	type args struct {
		b io.Reader
	}

	type testCase[T interface{ ~string }] struct {
		name string
		args args
		want *Error
	}
	tests := []testCase[string]{
		{
			name: "Success",
			args: args{
				b: bytes.NewReader([]byte("{" +
					"\"error\":\"bad_request\"," +
					"\"component\":\"error component\"," +
					"\"operation\":\"error operation\"," +
					"\"incorrect_value\":\"error incorrect value\"," +
					"\"http_status\":400," +
					"\"error_description\":\"some error\"" +
					"}")),
			},
			want: &Error{
				ErrorCode:      "bad_request",
				ErrorComponent: "error component",
				Operation:      "error operation",
				IncorrectValue: "error incorrect value",
				HTTPStatus:     http.StatusBadRequest,
				Err:            errors.New("some error"),
			},
		},
		{
			name: "Failure: reader error",
			args: args{
				b: &mockReader{err: errors.New("some error")},
			},
			want: &Error{
				ErrorCode:  "invalid_credential_request",
				HTTPStatus: http.StatusInternalServerError,
				Err:        errors.New("read OIDC4CI error: some error"),
			},
		},
		{
			name: "Failure: invalid body",
			args: args{
				b: bytes.NewReader([]byte("{")),
			},
			want: &Error{
				ErrorCode:  "invalid_credential_request",
				HTTPStatus: http.StatusInternalServerError,
				Err:        errors.New("decode OIDC4CI error from body: {, err: unexpected end of JSON input"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCredentialEndpointErrorResponse(tt.args.b)

			assert.Equal(t, tt.want.Error(), got.Error())
		})
	}
}

type mockReader struct {
	err error
}

func (r *mockReader) Read(_ []byte) (int, error) {
	return 0, r.err
}
