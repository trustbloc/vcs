/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package eventhandler -source=eventhandler_wrapper.go -mock_names service=MockEventHandler

package eventhandler

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

type service interface {
	HandleEvent(ctx context.Context, event *spi.Event) error
}

type Wrapper struct {
	svc    service
	tracer trace.Tracer
}

func Wrap(svc service, tracer trace.Tracer) *Wrapper {
	return &Wrapper{svc: svc, tracer: tracer}
}

func (w *Wrapper) HandleEvent(ctx context.Context, event *spi.Event) error {
	spanCtx, span := w.tracer.Start(ctx, "credentialstatus.HandleEvent", trace.WithAttributes(
		attribute.KeyValue{Key: "event_id", Value: attribute.StringValue(event.ID)},
		attribute.KeyValue{Key: "event_type", Value: attribute.StringValue(string(event.Type))},
	))
	defer span.End()

	err := w.svc.HandleEvent(spanCtx, event)
	if err != nil {
		span.RecordError(err)
		return err
	}

	return nil
}
