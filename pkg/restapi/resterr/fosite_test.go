/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
)

func TestNewFositeError(t *testing.T) {
	ctx, _ := createContext(http.MethodGet)
	got := NewFositeError(
		FositeIntrospectionError,
		ctx,
		NewMockFositeErrorWriter(gomock.NewController(t)),
		errors.New("some error"),
	)

	assert.Contains(t, got.Error(), "some error")

	want := &FositeError{
		err:                errors.New("some error"),
		code:               FositeIntrospectionError,
		ctx:                ctx,
		writer:             NewMockFositeErrorWriter(gomock.NewController(t)),
		authorizeRequester: nil,
		accessRequester:    nil,
	}

	if !reflect.DeepEqual(got, want) { //nolint:govet
		t.Errorf("NewFositeError() = %v, want %v", got, want)
	}

	ar := fosite.NewAccessRequest(nil)
	got = got.WithAccessRequester(ar)
	want.accessRequester = ar

	if !reflect.DeepEqual(got, want) { //nolint:govet
		t.Errorf("NewFositeError() = %v, want %v", got, want)
	}

	authReq := fosite.NewAuthorizeRequest()

	got = got.WithAuthorizeRequester(authReq)
	want.authorizeRequester = authReq

	if !reflect.DeepEqual(got, want) { //nolint:govet
		t.Errorf("NewFositeError() = %v, want %v", got, want)
	}
}

func TestFositeError_Write(t *testing.T) {
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))
	ctx, rw := createContext(http.MethodGet)
	type fields struct {
		code      FositeErrorCode
		getWriter func() fositeErrorWriter
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "OK FositeAuthorizeError",
			fields: fields{
				code: FositeAuthorizeError,
				getWriter: func() fositeErrorWriter {
					mockFositeErrWriter.EXPECT().
						WriteAuthorizeError(gomock.Any(), rw, gomock.Any(), gomock.Any()).Times(1)
					return mockFositeErrWriter
				},
			},
			wantErr: false,
		},
		{
			name: "OK FositeAccessError",
			fields: fields{
				code: FositeAccessError,
				getWriter: func() fositeErrorWriter {
					mockFositeErrWriter.EXPECT().
						WriteAccessError(gomock.Any(), rw, gomock.Any(), gomock.Any()).Times(1)
					return mockFositeErrWriter
				},
			},
			wantErr: false,
		},
		{
			name: "OK FositeIntrospectionError",
			fields: fields{
				code: FositeIntrospectionError,
				getWriter: func() fositeErrorWriter {
					mockFositeErrWriter.EXPECT().
						WriteIntrospectionError(gomock.Any(), rw, gomock.Any()).Times(1)
					return mockFositeErrWriter
				},
			},
			wantErr: false,
		},
		{
			name: "OK FositePARError",
			fields: fields{
				code: FositePARError,
				getWriter: func() fositeErrorWriter {
					mockFositeErrWriter.EXPECT().
						WritePushedAuthorizeError(gomock.Any(), rw, gomock.Any(), gomock.Any()).Times(1)
					return mockFositeErrWriter
				},
			},
			wantErr: false,
		},
		{
			name: "Error",
			fields: fields{
				code: -1,
				getWriter: func() fositeErrorWriter {
					return mockFositeErrWriter
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &FositeError{
				ctx:    ctx,
				code:   tt.fields.code,
				writer: tt.fields.getWriter(),
			}
			if err := e.Write(); (err != nil) != tt.wantErr {
				t.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
