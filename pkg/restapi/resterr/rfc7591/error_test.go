/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc7591

import (
	"errors"
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
			name:       "OK NewInvalidRedirectURIError",
			createFunc: NewInvalidRedirectURIError,
			want: &Error{
				ErrorCode:  invalidRedirectURI,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidClientMetadataError",
			createFunc: NewInvalidClientMetadataError,
			want: &Error{
				ErrorCode:  invalidClientMetadata,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewInvalidSoftwareStatementError",
			createFunc: NewInvalidSoftwareStatementError,
			want: &Error{
				ErrorCode:  invalidSoftwareStatement,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			name:       "OK NewUnapprovedSoftwareStatementError",
			createFunc: NewUnapprovedSoftwareStatementError,
			want: &Error{
				ErrorCode:  unapprovedSoftwareStatement,
				Err:        err,
				HTTPStatus: http.StatusBadRequest,
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
