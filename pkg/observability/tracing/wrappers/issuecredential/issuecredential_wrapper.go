/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package issuecredential . Service

package issuecredential

import (
	"context"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

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
	issuerSigningOpts []crypto.SigningOpts,
	profile *profileapi.Issuer,
) (*verifiable.Credential, error) {
	ctx, span := w.tracer.Start(ctx, "issuecredential.IssueCredential")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profile.ID))

	credential, err := w.svc.IssueCredential(ctx, vc, issuerSigningOpts, profile)
	if err != nil {
		return nil, err
	}

	return credential, nil
}
