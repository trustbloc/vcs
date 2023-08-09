/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package verifycredential . Service

//nolint:lll
package verifycredential

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
)

var _ Service = (*Wrapper)(nil) // make sure Wrapper implements verifycredential.ServiceInterface

type Service verifycredential.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) VerifyCredential(ctx context.Context, credential *verifiable.Credential, opts *verifycredential.Options, profile *profileapi.Verifier) ([]verifycredential.CredentialsVerificationCheckResult, error) {
	ctx, span := w.tracer.Start(ctx, "verifycredential.VerifyCredential")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))
	span.SetAttributes(attributeutil.JSON("opts", opts))

	res, err := w.svc.VerifyCredential(ctx, credential, opts, profile)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (w *Wrapper) ValidateCredentialProof(ctx context.Context, vcByte []byte, proofChallenge, proofDomain string, vcInVPValidation, isJWT bool) error {
	ctx, span := w.tracer.Start(ctx, "verifycredential.ValidateCredentialProof")
	defer span.End()

	span.SetAttributes(attribute.String("proof_challenge", proofChallenge))
	span.SetAttributes(attribute.String("proof_domain", proofDomain))
	span.SetAttributes(attribute.Bool("vc_in_vp_validation", vcInVPValidation))
	span.SetAttributes(attribute.Bool("is_jwt", isJWT))

	return w.svc.ValidateCredentialProof(ctx, vcByte, proofChallenge, proofDomain, vcInVPValidation, isJWT)
}

func (w *Wrapper) ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer string) error {
	ctx, span := w.tracer.Start(ctx, "verifycredential.ValidateCredentialProof")
	defer span.End()

	span.SetAttributes(attributeutil.JSON("vc_status", vcStatus))
	span.SetAttributes(attribute.String("issuer", issuer))

	return w.svc.ValidateVCStatus(ctx, vcStatus, issuer)
}

func (w *Wrapper) ValidateLinkedDomain(ctx context.Context, signingDID string) error {
	ctx, span := w.tracer.Start(ctx, "verifycredential.ValidateLinkedDomain")
	defer span.End()

	span.SetAttributes(attribute.String("signingDID", signingDID))

	return w.svc.ValidateLinkedDomain(ctx, signingDID)
}
