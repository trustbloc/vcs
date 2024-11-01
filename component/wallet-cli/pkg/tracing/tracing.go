/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"os"

	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

var logger = log.New("tracing")

// SpanExporterType specifies the type of span exporter used by tracer provider.
type SpanExporterType = string

const (
	tracerName = "https://github.com/trustbloc/wallet-cli"
)

func Initialize(serviceName string) trace.Tracer {
	tracerProvider := tracesdk.NewTracerProvider(
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ProcessPIDKey.Int(os.Getpid()),
		)),
	)

	// Register the TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(tracerProvider)

	// Propagate trace context via traceparent and tracestate headers (https://www.w3.org/TR/trace-context/).
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tracerProvider.Tracer(tracerName)
}
