// Package grpcclient provides a factory for creating gRPC client connections
// with the standard interceptor chain pre-configured.
//
// Usage:
//
//	conn, err := grpcclient.New(ctx, grpcclient.Config{
//	    Target:        "iam-service:50060",
//	    CallerService: "kyc-service",
//	    TLS:           false, // true in production
//	})
//	defer conn.Close()
//	stub := iamv1.NewIAMServiceClient(conn)
package grpcclient

import (
	"context"
	"fmt"
	"time"

	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config holds configuration for a gRPC client connection.
type Config struct {
	// Target is the gRPC server address, e.g. "iam-service:50060"
	Target string

	// CallerService is injected into outgoing metadata as x-caller-service.
	CallerService string

	// TLS enables TLS transport security (required in production).
	TLS bool

	// TLSCertFile is the path to the server CA certificate (for TLS).
	TLSCertFile string

	// DialTimeout is the maximum time to wait for the connection.
	// Default: 10 seconds.
	DialTimeout time.Duration

	// Log is the logger to use for client interceptors.
	Log zerolog.Logger
}

// New creates a new gRPC client connection with the standard interceptor chain:
//  1. OpenTelemetry tracing
//  2. Request-ID / trace-ID propagation
//  3. Structured logging
func New(ctx context.Context, cfg Config) (*grpc.ClientConn, error) {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	// Transport credentials
	var creds credentials.TransportCredentials
	if cfg.TLS {
		if cfg.TLSCertFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(cfg.TLSCertFile, "")
			if err != nil {
				return nil, fmt.Errorf("loading TLS cert %q: %w", cfg.TLSCertFile, err)
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, "")
		}
	} else {
		creds = insecure.NewCredentials()
	}

	// Build dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithChainUnaryInterceptor(
			middleware.ClientInterceptorChain(cfg.CallerService, cfg.Log)...,
		),
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, cfg.Target, opts...) //nolint:staticcheck
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", cfg.Target, err)
	}

	return conn, nil
}

// MustNew is like New but panics on error. Use only in tests or main().
func MustNew(ctx context.Context, cfg Config) *grpc.ClientConn {
	conn, err := New(ctx, cfg)
	if err != nil {
		panic(fmt.Sprintf("grpcclient.MustNew(%q): %v", cfg.Target, err))
	}
	return conn
}
