/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oauth2provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestWrapper_NewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewAuthorizeRequest(gomock.Any(), &http.Request{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewAuthorizeRequest(context.Background(), &http.Request{})
	require.NoError(t, err)
}

func TestWrapper_NewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewAuthorizeResponse(gomock.Any(), &fosite.AuthorizeRequest{}, &fosite.DefaultSession{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewAuthorizeResponse(context.Background(), &fosite.AuthorizeRequest{}, &fosite.DefaultSession{})
	require.NoError(t, err)
}

func TestWrapper_WriteAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteAuthorizeError(gomock.Any(), httptest.NewRecorder(), &fosite.AuthorizeRequest{}, nil).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteAuthorizeError(context.Background(), httptest.NewRecorder(), &fosite.AuthorizeRequest{}, nil)
}

func TestWrapper_WriteAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteAuthorizeResponse(gomock.Any(), httptest.NewRecorder(), &fosite.AuthorizeRequest{}, &fosite.AuthorizeResponse{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteAuthorizeResponse(context.Background(), httptest.NewRecorder(), &fosite.AuthorizeRequest{}, &fosite.AuthorizeResponse{})
}

func TestWrapper_NewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewAccessRequest(gomock.Any(), &http.Request{}, &fosite.DefaultSession{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewAccessRequest(context.Background(), &http.Request{}, &fosite.DefaultSession{})
	require.NoError(t, err)
}

func TestWrapper_NewAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewAccessResponse(gomock.Any(), &fosite.AccessRequest{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewAccessResponse(context.Background(), &fosite.AccessRequest{})
	require.NoError(t, err)
}

func TestWrapper_WriteAccessError(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteAccessError(gomock.Any(), rec, &fosite.AccessRequest{}, errors.New("access error")).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteAccessError(context.Background(), rec, &fosite.AccessRequest{}, errors.New("access error"))
}

func TestWrapper_WriteAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteAccessResponse(gomock.Any(), rec, &fosite.AccessRequest{}, &fosite.AccessResponse{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteAccessResponse(context.Background(), rec, &fosite.AccessRequest{}, &fosite.AccessResponse{})
}

func TestWrapper_NewRevocationRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewRevocationRequest(gomock.Any(), &http.Request{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	err := w.NewRevocationRequest(context.Background(), &http.Request{})
	require.NoError(t, err)
}

func TestWrapper_WriteRevocationResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteRevocationResponse(gomock.Any(), rec, nil).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteRevocationResponse(context.Background(), rec, nil)
}

func TestWrapper_IntrospectToken(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().IntrospectToken(gomock.Any(), "token", fosite.AccessToken, &fosite.DefaultSession{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, _, err := w.IntrospectToken(context.Background(), "token", fosite.AccessToken, &fosite.DefaultSession{})
	require.NoError(t, err)
}

func TestWrapper_NewIntrospectionRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewIntrospectionRequest(gomock.Any(), &http.Request{}, &fosite.DefaultSession{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewIntrospectionRequest(context.Background(), &http.Request{}, &fosite.DefaultSession{})
	require.NoError(t, err)
}

func TestWrapper_WriteIntrospectionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteIntrospectionError(gomock.Any(), rec, errors.New("introspection error")).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteIntrospectionError(context.Background(), rec, errors.New("introspection error"))
}

func TestWrapper_WriteIntrospectionResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WriteIntrospectionResponse(gomock.Any(), rec, &fosite.IntrospectionResponse{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WriteIntrospectionResponse(context.Background(), rec, &fosite.IntrospectionResponse{})
}

func TestWrapper_NewPushedAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), &http.Request{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewPushedAuthorizeRequest(context.Background(), &http.Request{})
	require.NoError(t, err)
}

func TestWrapper_NewPushedAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)

	provider := NewMockProvider(ctrl)
	provider.EXPECT().NewPushedAuthorizeResponse(gomock.Any(), &fosite.AuthorizeRequest{}, &fosite.DefaultSession{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.NewPushedAuthorizeResponse(context.Background(), &fosite.AuthorizeRequest{}, &fosite.DefaultSession{})
	require.NoError(t, err)
}

func TestWrapper_WritePushedAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WritePushedAuthorizeResponse(gomock.Any(), rec, &fosite.AuthorizeRequest{}, &fosite.PushedAuthorizeResponse{}).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WritePushedAuthorizeResponse(context.Background(), rec, &fosite.AuthorizeRequest{}, &fosite.PushedAuthorizeResponse{})
}

func TestWrapper_WritePushedAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	rec := httptest.NewRecorder()

	provider := NewMockProvider(ctrl)
	provider.EXPECT().WritePushedAuthorizeError(gomock.Any(), rec, &fosite.AuthorizeRequest{}, errors.New("par error")).Times(1)

	w := Wrap(provider, trace.NewNoopTracerProvider().Tracer(""))

	w.WritePushedAuthorizeError(context.Background(), rec, &fosite.AuthorizeRequest{}, errors.New("par error"))
}
