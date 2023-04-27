/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package component . Service

//nolint:lll
package component

import (
	"context"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

var _ Service = (*Wrapper)(nil) // make sure Wrapper implements credentialstatus.ServiceInterface

type Service credentialstatus.ServiceInterface

type Wrapper struct {
	svc    Service
	tracer trace.Tracer
}

func Wrap(svc Service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) CreateStatusListEntry(
	ctx context.Context, profileID, profileVersion, credentialID string) (*credentialstatus.StatusListEntry, error) {
	ctx, span := w.tracer.Start(ctx, "credentialstatus.CreateStatusListEntry")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profileID))
	span.SetAttributes(attribute.String("profile_version", profileVersion))
	span.SetAttributes(attribute.String("credential_id", credentialID))

	entry, err := w.svc.CreateStatusListEntry(ctx, profileID, profileVersion, credentialID)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (w *Wrapper) GetStatusListVC(
	ctx context.Context,
	profileGroupID profileapi.ID,
	statusID string) (*credentialstatus.CSL, error) {
	ctx, span := w.tracer.Start(ctx, "credentialstatus.GetStatusListVC")
	defer span.End()

	span.SetAttributes(attribute.String("profile_group_id", profileGroupID))
	span.SetAttributes(attribute.String("status_id", statusID))

	vc, err := w.svc.GetStatusListVC(ctx, profileGroupID, statusID)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (w *Wrapper) UpdateVCStatus(ctx context.Context, params credentialstatus.UpdateVCStatusParams) error {
	ctx, span := w.tracer.Start(ctx, "credentialstatus.UpdateVCStatus")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", params.ProfileID))
	span.SetAttributes(attribute.String("profile_version", params.ProfileVersion))
	span.SetAttributes(attributeutil.JSON("params", params))

	err := w.svc.UpdateVCStatus(ctx, params)
	if err != nil {
		return err
	}

	return nil
}

func (w *Wrapper) Resolve(ctx context.Context, statusListVCURI string) (*verifiable.Credential, error) {
	ctx, span := w.tracer.Start(ctx, "credentialstatus.Resolve")
	defer span.End()

	span.SetAttributes(attribute.String("status_list_vc_uri", statusListVCURI))

	vc, err := w.svc.Resolve(ctx, statusListVCURI)
	if err != nil {
		return nil, err
	}

	return vc, nil
}
