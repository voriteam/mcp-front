package telemetry

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Provider wraps the OTel log and trace provider lifecycle.
type Provider struct {
	loggerProvider *sdklog.LoggerProvider
	tracerProvider *sdktrace.TracerProvider
}

// NewProvider sets up OTel log and trace providers. When an OTLP endpoint is
// configured via OTEL_EXPORTER_OTLP_ENDPOINT or the logs/traces variants, the
// respective exporters are used. Otherwise providers are set up without
// exporters — spans are still created (giving valid trace IDs for log
// correlation) but nothing is shipped.
func NewProvider(ctx context.Context) (*Provider, error) {
	otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	logProvider, err := setupLogProvider(ctx, otlpEndpoint)
	if err != nil {
		return nil, err
	}

	traceProvider, err := setupTraceProvider(ctx, otlpEndpoint)
	if err != nil {
		return nil, err
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		loggerProvider: logProvider,
		tracerProvider: traceProvider,
	}, nil
}

func setupLogProvider(ctx context.Context, otlpEndpoint string) (*sdklog.LoggerProvider, error) {
	if otlpEndpoint == "" && os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") == "" {
		return sdklog.NewLoggerProvider(), nil
	}

	exporter, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	global.SetLoggerProvider(provider)
	return provider, nil
}

func setupTraceProvider(ctx context.Context, otlpEndpoint string) (*sdktrace.TracerProvider, error) {
	var opts []sdktrace.TracerProviderOption

	if otlpEndpoint != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(provider)
	return provider, nil
}

// Shutdown flushes and stops all providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	var errs []error
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer shutdown: %w", err))
		}
	}
	if p.loggerProvider != nil {
		if err := p.loggerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("logger shutdown: %w", err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
