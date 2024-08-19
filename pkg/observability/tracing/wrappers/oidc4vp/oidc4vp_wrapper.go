/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package oidc4vp . Service

//nolint:lll
package oidc4vp

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vc-go/presexch"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

type Service oidc4vp.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) InitiateOidcInteraction(
	ctx context.Context,
	presentationDefinition *presexch.PresentationDefinition,
	purpose string,
	customScopes []string,
	customURLScheme string,
	profile *profileapi.Verifier) (*oidc4vp.InteractionInfo, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.InitiateOidcInteraction")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))
	span.SetAttributes(attribute.String("purpose", purpose))
	span.SetAttributes(attribute.StringSlice("custom_copes", customScopes))

	resp, err := w.svc.InitiateOidcInteraction(ctx,
		presentationDefinition, purpose, customScopes, customURLScheme, profile)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (w *Wrapper) VerifyOIDCVerifiablePresentation(ctx context.Context, txID oidc4vp.TxID, authResponse *oidc4vp.AuthorizationResponseParsed) error {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.VerifyOIDCVerifiablePresentation")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(txID)))

	return w.svc.VerifyOIDCVerifiablePresentation(ctx, txID, authResponse)
}

func (w *Wrapper) GetTx(ctx context.Context, id oidc4vp.TxID) (*oidc4vp.Transaction, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.GetTx")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(id)))

	tx, err := w.svc.GetTx(ctx, id)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (w *Wrapper) RetrieveClaims(ctx context.Context, tx *oidc4vp.Transaction, profile *profileapi.Verifier) map[string]oidc4vp.CredentialMetadata {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.RetrieveClaims")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(tx.ID)))

	cm := w.svc.RetrieveClaims(ctx, tx, profile)

	return cm
}

func (w *Wrapper) DeleteClaims(ctx context.Context, claimsID string) error {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.DeleteClaims")
	defer span.End()

	span.SetAttributes(attribute.String("claims_id", claimsID))

	return w.svc.DeleteClaims(ctx, claimsID)
}

func (w *Wrapper) HandleWalletNotification(ctx context.Context, req *oidc4vp.WalletNotification) error {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.HandleWalletNotification")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(req.TxID)))
	span.SetAttributes(attribute.String("event", req.Error))

	return w.svc.HandleWalletNotification(ctx, req)
}
