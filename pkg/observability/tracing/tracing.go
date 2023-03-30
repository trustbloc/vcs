/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"context"
	"fmt"
	"os"

	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
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
	None   SpanExporterType = ""
	Jaeger SpanExporterType = "JAEGER"
	Stdout SpanExporterType = "STDOUT"
)

const (
	JaegerAgentEndpointEnvKey     = "OTEL_EXPORTER_JAEGER_AGENT_HOST"
	JaegerCollectorEndpointEnvKey = "OTEL_EXPORTER_JAEGER_ENDPOINT"
	tracerName                    = "https://github.com/trustbloc/vcs"
)

// Initialize creates and registers globally a new tracer provider with specified span exporter.
// Return values are:
// - func() - Should be called to gracefully shut down the tracer provider before the process terminates.
// - trace.Tracer - Used to start new spans.
// - error - An error if the tracer provider could not be initialized or nil if successful.
func Initialize(exporter SpanExporterType, serviceName string) (func(), trace.Tracer, error) {
	if exporter == None {
		return func() {}, trace.NewNoopTracerProvider().Tracer(""), nil
	}

	var tracerProvider *tracesdk.TracerProvider

	var (
		spanExporter tracesdk.SpanExporter
		err          error
	)

	switch exporter {
	case Jaeger:
		var endpoint jaeger.EndpointOption

		switch {
		case os.Getenv(JaegerAgentEndpointEnvKey) != "":
			endpoint = jaeger.WithAgentEndpoint()
		case os.Getenv(JaegerCollectorEndpointEnvKey) != "":
			endpoint = jaeger.WithCollectorEndpoint()
		default:
			return nil, nil, fmt.Errorf("neither agent nor collector endpoint is provided")
		}

		spanExporter, err = jaeger.New(endpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("create jaeger exporter: %w", err)
		}
	case Stdout:
		spanExporter, err = stdouttrace.New()
		if err != nil {
			return nil, nil, fmt.Errorf("create stdout exporter: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported exporter type: %s", exporter)
	}

	tracerProvider = tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(spanExporter),
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

	return func() {
		if err = tracerProvider.Shutdown(context.Background()); err != nil {
			logger.Warn("Error shutting down tracer provider", log.WithError(err))
		}
	}, tracerProvider.Tracer(tracerName), nil
}
