/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFositeError(t *testing.T) {
	ctx, _ := createContext()
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
	ctx, rw := createContext()
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

func createContext() (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestNewFositeUnauthorizedClientErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositeAuthUnauthorizedClientErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrUnauthorizedClient,
		code:   FositeAuthorizeError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestNewFositePARUnauthorizedClientErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositePARUnauthorizedClientErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrUnauthorizedClient,
		code:   FositePARError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestNewFositeAuthInvalidRequestErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositeAuthInvalidRequestErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrInvalidRequest,
		code:   FositeAuthorizeError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestNewFositePARInvalidRequestErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositePARInvalidRequestErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrInvalidRequest,
		code:   FositePARError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestNewFositeAccessTokenInvalidTokenErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositeAccessTokenInvalidTokenErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrInvalidTokenFormat,
		code:   FositeAccessError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestNewFositeIntrospectTokenInvalidTokenErr(t *testing.T) {
	ctx, _ := createContext()
	mockFositeErrWriter := NewMockFositeErrorWriter(gomock.NewController(t))

	got := NewFositeIntrospectTokenInvalidTokenErr(ctx, mockFositeErrWriter)

	want := &FositeError{
		err:    fosite.ErrInvalidTokenFormat,
		code:   FositeIntrospectionError,
		ctx:    ctx,
		writer: mockFositeErrWriter,
	}

	require.Equal(t, want, got)
}

func TestFositeError_Unwrap(t *testing.T) {
	err := errors.New("some error")
	e := &FositeError{err: err}

	assert.Equal(t, err, e.Unwrap())
}
