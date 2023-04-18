/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4vp

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

func TestWrapper_InitiateOidcInteraction(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().InitiateOidcInteraction(gomock.Any(), &presexch.PresentationDefinition{}, "purpose", &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.InitiateOidcInteraction(context.Background(), &presexch.PresentationDefinition{}, "purpose", &profileapi.Verifier{})
	require.NoError(t, err)
}

func TestWrapper_VerifyOIDCVerifiablePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().VerifyOIDCVerifiablePresentation(gomock.Any(), oidc4vp.TxID("txID"), []*oidc4vp.ProcessedVPToken{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.VerifyOIDCVerifiablePresentation(context.Background(), "txID", []*oidc4vp.ProcessedVPToken{})
	require.NoError(t, err)
}

func TestWrapper_GetTx(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txID")).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.GetTx(context.Background(), "txID")
	require.NoError(t, err)
}

func TestWrapper_RetrieveClaims(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().RetrieveClaims(gomock.Any(), &oidc4vp.Transaction{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_ = w.RetrieveClaims(context.Background(), &oidc4vp.Transaction{})
}

func TestWrapper_DeleteClaims(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().DeleteClaims(gomock.Any(), "claimsID").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_ = w.DeleteClaims(context.Background(), "claimsID")
}
