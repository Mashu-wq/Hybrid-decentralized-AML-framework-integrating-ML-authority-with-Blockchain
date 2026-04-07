// Package logger provides structured JSON logging using zerolog.
// All services must use this package for consistent log formatting.
package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// contextKey is unexported to prevent collisions.
type contextKey struct{ name string }

var loggerKey = contextKey{"logger"}

// Config holds logger configuration.
type Config struct {
	Level       string // debug, info, warn, error
	ServiceName string
	Environment string
	Pretty      bool // human-readable output for local dev
}

// Init initializes the global zerolog logger with structured fields.
// Call once at service startup.
func Init(cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339Nano

	var w io.Writer = os.Stdout
	if cfg.Pretty {
		w = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	}

	logger := zerolog.New(w).
		With().
		Timestamp().
		Str("service", cfg.ServiceName).
		Str("environment", cfg.Environment).
		Logger()

	log.Logger = logger
	return logger
}

// FromContext retrieves the logger stored in a context.
// Falls back to the global logger if none found.
func FromContext(ctx context.Context) zerolog.Logger {
	if l, ok := ctx.Value(loggerKey).(zerolog.Logger); ok {
		return l
	}
	return log.Logger
}

// WithContext stores a logger in the context.
func WithContext(ctx context.Context, l zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// WithTraceID returns a logger enriched with trace and span IDs.
func WithTraceID(l zerolog.Logger, traceID, spanID string) zerolog.Logger {
	return l.With().
		Str("trace_id", traceID).
		Str("span_id", spanID).
		Logger()
}

// WithRequestID returns a logger enriched with an HTTP request ID.
func WithRequestID(l zerolog.Logger, requestID string) zerolog.Logger {
	return l.With().Str("request_id", requestID).Logger()
}
