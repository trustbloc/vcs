/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4ci

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestWrapper_InitiateIssuance(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().InitiateIssuance(gomock.Any(), &oidc4ci.InitiateIssuanceRequest{}, &profile.Issuer{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.InitiateIssuance(context.Background(), &oidc4ci.InitiateIssuanceRequest{}, &profile.Issuer{})
	require.NoError(t, err)
}

func TestWrapper_PushAuthorizationDetails(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().PushAuthorizationDetails(gomock.Any(), "opState", &oidc4ci.AuthorizationDetails{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.PushAuthorizationDetails(context.Background(), "opState", &oidc4ci.AuthorizationDetails{})
	require.NoError(t, err)
}

func TestWrapper_PrepareClaimDataAuthorizationRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().PrepareClaimDataAuthorizationRequest(gomock.Any(), &oidc4ci.PrepareClaimDataAuthorizationRequest{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.PrepareClaimDataAuthorizationRequest(context.Background(), &oidc4ci.PrepareClaimDataAuthorizationRequest{})
	require.NoError(t, err)
}

func TestWrapper_StoreAuthorizationCode(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().StoreAuthorizationCode(gomock.Any(), "opState", "code").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.StoreAuthorizationCode(context.Background(), "opState", "code")
	require.NoError(t, err)
}

func TestWrapper_ExchangeAuthorizationCode(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ExchangeAuthorizationCode(gomock.Any(), "opState").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.ExchangeAuthorizationCode(context.Background(), "opState")
	require.NoError(t, err)
}

func TestWrapper_ValidatePreAuthorizedCodeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), "code", "pin").Return(&oidc4ci.Transaction{ID: "id"}, nil)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.ValidatePreAuthorizedCodeRequest(context.Background(), "code", "pin")
	require.NoError(t, err)
}

func TestWrapper_PrepareCredential(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().PrepareCredential(gomock.Any(), &oidc4ci.PrepareCredential{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.PrepareCredential(context.Background(), &oidc4ci.PrepareCredential{})
	require.NoError(t, err)
}
