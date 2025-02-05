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
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/presexch"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

func TestWrapper_InitiateOidcInteraction(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().InitiateOidcInteraction(gomock.Any(), &presexch.PresentationDefinition{}, "purpose", []string{"additionalScope"}, "", &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.InitiateOidcInteraction(context.Background(), &presexch.PresentationDefinition{}, "purpose", []string{"additionalScope"}, "", &profileapi.Verifier{})
	require.NoError(t, err)
}

func TestWrapper_VerifyOIDCVerifiablePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().VerifyOIDCVerifiablePresentation(gomock.Any(), oidc4vp.TxID("txID"), &oidc4vp.AuthorizationResponseParsed{VPTokens: []*oidc4vp.ProcessedVPToken{}}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.VerifyOIDCVerifiablePresentation(context.Background(), "txID", &oidc4vp.AuthorizationResponseParsed{VPTokens: []*oidc4vp.ProcessedVPToken{}})
	require.NoError(t, err)
}

func TestWrapper_GetTx(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().GetTx(gomock.Any(), oidc4vp.TxID("txID")).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.GetTx(context.Background(), "txID")
	require.NoError(t, err)
}

func TestWrapper_RetrieveClaims(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().RetrieveClaims(gomock.Any(), &oidc4vp.Transaction{}, &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_ = w.RetrieveClaims(context.Background(), &oidc4vp.Transaction{}, &profileapi.Verifier{})
}

func TestWrapper_DeleteClaims(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().DeleteClaims(gomock.Any(), "claimsID").Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_ = w.DeleteClaims(context.Background(), "claimsID")
}

func TestWrapper_HandleWalletNotification(t *testing.T) {
	ctrl := gomock.NewController(t)

	ack := &oidc4vp.WalletNotification{
		TxID:             oidc4vp.TxID(uuid.NewString()),
		Error:            uuid.NewString(),
		ErrorDescription: uuid.NewString(),
	}

	svc := NewMockService(ctrl)
	svc.EXPECT().HandleWalletNotification(gomock.Any(), ack).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_ = w.HandleWalletNotification(context.Background(), ack)
}

func TestWrapper_SendTransactionEvent(t *testing.T) {
	ctrl := gomock.NewController(t)

	txID := oidc4vp.TxID(uuid.NewString())
	eventType := spi.VerifierOIDCInteractionQRScanned

	svc := NewMockService(ctrl)
	svc.EXPECT().SendTransactionEvent(gomock.Any(), txID, eventType).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_ = w.SendTransactionEvent(context.Background(), txID, eventType)
}
