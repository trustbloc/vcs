/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package oidc4ci . Service

//nolint:lll
package oidc4ci

import (
	"context"

	"github.com/samber/lo"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

type Service oidc4ci.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) InitiateIssuance(
	ctx context.Context,
	req *oidc4ci.InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*oidc4ci.InitiateIssuanceResponse, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4ci.InitiateIssuance")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))
	span.SetAttributes(attributeutil.JSON("initiate_issuance_request", req, attributeutil.WithRedacted("ClaimData")))

	if req.ClaimData != nil {
		span.SetAttributes(attribute.StringSlice("claim_keys", lo.Keys(req.ClaimData)))
	}

	resp, err := w.svc.InitiateIssuance(ctx, req, profile)
	if err != nil {
		return nil, err
	}

	span.SetAttributes(attribute.String("tx_id", string(resp.TxID)))

	return resp, nil
}

func (w *Wrapper) PushAuthorizationDetails(ctx context.Context, opState string, ad *oidc4ci.AuthorizationDetails) error {
	return w.svc.PushAuthorizationDetails(ctx, opState, ad)
}

func (w *Wrapper) PrepareClaimDataAuthorizationRequest(ctx context.Context, req *oidc4ci.PrepareClaimDataAuthorizationRequest) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error) {
	return w.svc.PrepareClaimDataAuthorizationRequest(ctx, req)
}

func (w *Wrapper) StoreAuthorizationCode(ctx context.Context, opState string, code string, flowData *common.WalletInitiatedFlowData) (oidc4ci.TxID, error) {
	return w.svc.StoreAuthorizationCode(ctx, opState, code, flowData)
}

func (w *Wrapper) ExchangeAuthorizationCode(ctx context.Context, opState, clientID, clientAttestationType, clientAttestation string) (*oidc4ci.ExchangeAuthorizationCodeResult, error) {
	return w.svc.ExchangeAuthorizationCode(ctx, opState, clientID, clientAttestationType, clientAttestation)
}

func (w *Wrapper) ValidatePreAuthorizedCodeRequest(ctx context.Context, preAuthorizedCode, pin, clientID, clientAttestationType, clientAttestation string) (*oidc4ci.Transaction, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4ci.ValidatePreAuthorizedCodeRequest")
	defer span.End()

	span.SetAttributes(attribute.String("pre-authorized_code", preAuthorizedCode))
	span.SetAttributes(attribute.String("pin", pin))
	span.SetAttributes(attribute.String("client_id", clientID))

	tx, err := w.svc.ValidatePreAuthorizedCodeRequest(ctx, preAuthorizedCode, pin, clientID, clientAttestationType, clientAttestation)
	if err != nil {
		return nil, err
	}

	span.SetAttributes(attribute.String("tx_id", string(tx.ID)))

	return tx, nil
}

func (w *Wrapper) PrepareCredential(
	ctx context.Context,
	req *oidc4ci.PrepareCredential,
) (*oidc4ci.PrepareCredentialResult, error) {
	ctx, span := w.tracer.Start(ctx, "oidc4ci.PrepareCredential")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", string(req.TxID)))
	span.SetAttributes(attributeutil.JSON("prepare_credential_request", req))

	res, err := w.svc.PrepareCredential(ctx, req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
