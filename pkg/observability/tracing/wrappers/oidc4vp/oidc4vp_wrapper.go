/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package oidc4vp . Service

//nolint:lll
package oidc4vp

import (
	"context"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
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

func (w *Wrapper) InitiateOidcInteraction(ctx context.Context, presentationDefinition *presexch.PresentationDefinition, purpose string, profile *profileapi.Verifier) (*oidc4vp.InteractionInfo, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.InitiateOidcInteraction")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))
	span.SetAttributes(attribute.String("purpose", purpose))
	span.SetAttributes(attributeutil.JSON("presentation_definition", presentationDefinition))

	resp, err := w.svc.InitiateOidcInteraction(ctx, presentationDefinition, purpose, profile)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (w *Wrapper) VerifyOIDCVerifiablePresentation(ctx context.Context, txID oidc4vp.TxID, token []*oidc4vp.ProcessedVPToken) error {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.VerifyOIDCVerifiablePresentation")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(txID)))
	span.SetAttributes(attributeutil.JSON("token", token))

	if err := w.svc.VerifyOIDCVerifiablePresentation(ctx, txID, token); err != nil {
		return err
	}

	return nil
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

func (w *Wrapper) RetrieveClaims(ctx context.Context, tx *oidc4vp.Transaction) map[string]oidc4vp.CredentialMetadata {
	ctx, span := w.tracer.Start(ctx, "oidc4vp.GetTx")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(tx.ID)))
	span.SetAttributes(attributeutil.JSON("tx", tx))

	cm := w.svc.RetrieveClaims(ctx, tx)

	return cm
}
