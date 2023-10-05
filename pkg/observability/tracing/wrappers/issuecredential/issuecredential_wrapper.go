/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package issuecredential . Service

package issuecredential

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

var _ Service = (*Wrapper)(nil) // make sure Wrapper implements issuecredential.ServiceInterface

type Service issuecredential.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) IssueCredential(
	ctx context.Context,
	vc *verifiable.Credential,
	profile *profileapi.Issuer,
	opts ...issuecredential.Opts,
) (*verifiable.Credential, error) {
	ctx, span := w.tracer.Start(ctx, "issuecredential.IssueCredential")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))

	credential, err := w.svc.IssueCredential(ctx, vc, profile, opts...)
	if err != nil {
		return nil, err
	}

	return credential, nil
}
