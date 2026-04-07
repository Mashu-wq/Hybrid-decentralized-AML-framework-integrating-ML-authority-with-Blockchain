package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fraud-detection/shared/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Tracing starts an OpenTelemetry span for each HTTP request.
// Incoming W3C Trace-Context (traceparent / tracestate) and B3 headers are
// extracted so that spans from upstream clients are linked correctly.
// The resulting trace ID is echoed as X-Trace-ID for client-side correlation.
func Tracing(next http.Handler) http.Handler {
	tracer := tracing.Tracer("api-gateway")
	propagator := otel.GetTextMapPropagator()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract any upstream trace context carried in HTTP headers.
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Start a new span named after the HTTP method and coarsened path.
		spanName := fmt.Sprintf("%s %s", r.Method, coarsenPath(r.URL.Path))
		ctx, span := tracer.Start(ctx, spanName)
		defer span.End()

		span.SetAttributes(
			semconv.HTTPMethod(r.Method),
			semconv.HTTPTarget(r.URL.RequestURI()),
			attribute.String("http.host", r.Host),
			attribute.String("http.user_agent", r.UserAgent()),
			attribute.String("http.request_id", r.Header.Get("X-Request-ID")),
		)

		// Inject updated trace context into the outgoing (proxy) request headers
		// so downstream services receive the correct traceparent.
		propagator.Inject(ctx, propagation.HeaderCarrier(r.Header))

		// Let clients correlate their request with the distributed trace.
		traceID := tracing.TraceID(ctx)
		if traceID != "" {
			w.Header().Set("X-Trace-ID", traceID)
		}

		cw := newCaptureWriter(w)
		next.ServeHTTP(cw, r.WithContext(ctx))

		span.SetAttributes(attribute.Int("http.status_code", cw.statusCode))
	})
}

// coarsenPath replaces UUID / numeric path segments with "{id}" to avoid
// high-cardinality span names in Jaeger.
func coarsenPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if isID(p) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func isID(s string) bool {
	if len(s) == 0 {
		return false
	}
	// UUID pattern: 8-4-4-4-12 hex chars
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	// Pure numeric segment
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 4
}
