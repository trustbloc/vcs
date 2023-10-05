/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package verifypresentation . Service

package verifypresentation

import (
	"context"
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var _ Service = (*Wrapper)(nil) // make sure Wrapper implements verifypresentation.ServiceInterface

type Service verifypresentation.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) VerifyPresentation(
	ctx context.Context,
	presentation *verifiable.Presentation,
	opts *verifypresentation.Options,
	profile *profileapi.Verifier,
) ([]verifypresentation.PresentationVerificationCheckResult, map[string][]string, error) {
	ctx, span := w.tracer.Start(ctx, "verifypresentation.VerifyPresentation")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))

	if opts != nil {
		span.SetAttributes(attributeutil.JSON("opts", opts))
	}

	res, claimKeys, err := w.svc.VerifyPresentation(ctx, presentation, opts, profile)
	w.setClaimKeys(span, claimKeys)

	if err != nil {
		return nil, claimKeys, err
	}

	return res, claimKeys, nil
}

func (w *Wrapper) setClaimKeys(
	span trace.Span,
	claimKeys map[string][]string,
) {
	for id, key := range claimKeys {
		span.SetAttributes(attribute.StringSlice(fmt.Sprintf("claim_keys_%s", id), key))
	}
}
