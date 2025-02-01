/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRFCError_MarshalJSON(t *testing.T) {
	type testCase[T interface{ ~string }] struct {
		name    string
		e       RFCError[T]
		want    []byte
		wantErr assert.ErrorAssertionFunc
	}
	tests := []testCase[string]{
		{
			name: "Success: with usePublicAPIResponse",
			e: RFCError[string]{
				ErrorCode:            "bad_request",
				ErrorComponent:       "error component",
				Operation:            "error operation",
				IncorrectValue:       "error incorrect value",
				HTTPStatus:           http.StatusBadRequest,
				Err:                  errors.New("some error"),
				usePublicAPIResponse: true,
			},
			want: []byte("{" +
				"\"error\":\"bad_request\"," +
				"\"error_description\":\"bad_request[component: error component; operation: error operation; " +
				"incorrect value: error incorrect value; http status: 400]: some error\"}"),
			wantErr: assert.NoError,
		},
		{
			name: "Success: without usePublicAPIResponse",
			e: RFCError[string]{
				ErrorCode:      "bad_request",
				ErrorComponent: "error component",
				Operation:      "error operation",
				IncorrectValue: "error incorrect value",
				HTTPStatus:     http.StatusBadRequest,
				Err:            errors.New("some error"),
			},
			want: []byte("{" +
				"\"error\":\"bad_request\"," +
				"\"component\":\"error component\"," +
				"\"operation\":\"error operation\"," +
				"\"incorrect_value\":\"error incorrect value\"," +
				"\"http_status\":400," +
				"\"error_description\":\"some error\"" +
				"}"),
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.e.MarshalJSON()
			if !tt.wantErr(t, err, "MarshalJSON()") {
				return
			}
			assert.Equalf(t, tt.want, got, "MarshalJSON()")
		})
	}
}

func TestRFCError_UnmarshalJSON(t *testing.T) {
	type args struct {
		b []byte
	}

	type testCase[T interface{ ~string }] struct {
		name    string
		args    args
		want    RFCError[T]
		wantErr assert.ErrorAssertionFunc
	}
	tests := []testCase[string]{
		{
			name: "Success",
			args: args{
				b: []byte("{" +
					"\"error\":\"bad_request\"," +
					"\"component\":\"error component\"," +
					"\"operation\":\"error operation\"," +
					"\"incorrect_value\":\"error incorrect value\"," +
					"\"http_status\":400," +
					"\"error_description\":\"some error\"" +
					"}"),
			},
			want: RFCError[string]{
				ErrorCode:      "bad_request",
				ErrorComponent: "error component",
				Operation:      "error operation",
				IncorrectValue: "error incorrect value",
				HTTPStatus:     http.StatusBadRequest,
				Err:            errors.New("some error"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "Failure",
			args: args{
				b: []byte("{"),
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := RFCError[string]{}

			err := e.UnmarshalJSON(tt.args.b)

			if !tt.wantErr(t, err) {
				return
			}

			assert.Equal(t, tt.want, e)
		})
	}
}

func TestRFCError_General(t *testing.T) {
	err := RFCError[string]{
		ErrorCode: "bad_request",
		Err:       errors.New("some error"),
	}

	assert.Equal(t, "bad_request", err.Code())
	assert.Equal(t, errors.New("some error"), err.Unwrap())
	assert.Equal(t, "bad_request[]: some error", err.Error())

	_ = err.WithComponent("component")

	assert.Equal(t, "component", err.Component())
	assert.Equal(t, "bad_request[component: component]: some error", err.Error())

	_ = err.WithOperation("operation")

	assert.Equal(t, "bad_request[component: component; operation: operation]: some error", err.Error())

	_ = err.WithIncorrectValue("incorrectValue")

	assert.Equal(t, "bad_request[component: component; operation: operation; "+
		"incorrect value: incorrectValue]: some error", err.Error())

	_ = err.WithHTTPStatusField(http.StatusOK)

	assert.Equal(t, "bad_request[component: component; operation: operation; "+
		"incorrect value: incorrectValue; http status: 200]: some error", err.Error())

	_ = err.WithErrorPrefix("err prefix")

	assert.Equal(t, "bad_request[component: component; operation: operation; "+
		"incorrect value: incorrectValue; http status: 200]: err prefix: some error", err.Error())

	_ = err.UsePublicAPIResponse()

	assert.True(t, err.usePublicAPIResponse)
}
