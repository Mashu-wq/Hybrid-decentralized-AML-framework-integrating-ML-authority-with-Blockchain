// Package main is the entry point for the API Gateway service.
// The gateway is the single ingress point for all external traffic.
// It enforces:
//   - Request ID injection (X-Request-ID)
//   - Distributed tracing (OpenTelemetry → Jaeger)
//   - Security headers (CSP, HSTS, X-Frame-Options, …)
//   - CORS with origin whitelist
//   - Token-bucket rate limiting (per API key / IP / caller service)
//   - JWT validation via IAM service gRPC (cached for performance)
//
// Authenticated requests are forwarded to the appropriate downstream service
// via httputil.ReverseProxy.  /health and /metrics are handled locally.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	iamv1 "github.com/fraud-detection/proto/gen/go/iam/v1"
	"github.com/fraud-detection/api-gateway/internal/config"
	"github.com/fraud-detection/api-gateway/internal/health"
	"github.com/fraud-detection/api-gateway/internal/metrics"
	"github.com/fraud-detection/api-gateway/internal/middleware"
	"github.com/fraud-detection/api-gateway/internal/proxy"
	"github.com/fraud-detection/shared/grpcclient"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/tracing"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// -------------------------------------------------------------------------
	// Configuration
	// -------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// -------------------------------------------------------------------------
	// Logger
	// -------------------------------------------------------------------------
	log := logger.Init(logger.Config{
		Level:       cfg.LogLevel,
		ServiceName: cfg.ServiceName,
		Environment: cfg.Environment,
		Pretty:      cfg.Environment == "development",
	})

	log.Info().
		Str("service", cfg.ServiceName).
		Str("env", cfg.Environment).
		Int("port", cfg.Port).
		Msg("API Gateway starting")

	// -------------------------------------------------------------------------
	// Distributed tracing
	// -------------------------------------------------------------------------
	shutdownTracer, err := tracing.InitTracer(tracing.Config{
		ServiceName:    cfg.ServiceName,
		ServiceVersion: "1.0.0",
		Environment:    cfg.Environment,
		JaegerEndpoint: cfg.JaegerEndpoint,
		SampleRate:     1.0,
	})
	if err != nil {
		log.Warn().Err(err).Msg("tracer init failed — continuing without tracing")
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracer(ctx); err != nil {
				log.Error().Err(err).Msg("tracer shutdown error")
			}
		}()
	}

	// -------------------------------------------------------------------------
	// IAM gRPC client (for ValidateToken)
	// -------------------------------------------------------------------------
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dialCancel()

	iamConn, err := grpcclient.New(dialCtx, grpcclient.Config{
		Target:        cfg.IAMServiceAddr,
		CallerService: cfg.ServiceName,
		TLS:           false,
		Log:           log,
	})
	if err != nil {
		// A failed IAM connection is fatal — the gateway cannot validate tokens.
		return fmt.Errorf("connect to IAM service at %q: %w", cfg.IAMServiceAddr, err)
	}
	defer iamConn.Close()
	iamClient := iamv1.NewIAMServiceClient(iamConn)
	log.Info().Str("addr", cfg.IAMServiceAddr).Msg("IAM gRPC client ready")

	// -------------------------------------------------------------------------
	// Reverse proxy router
	// -------------------------------------------------------------------------
	router, err := proxy.New(proxy.ServiceAddrs{
		IAM:         cfg.Services.IAM,
		KYC:         cfg.Services.KYC,
		Transaction: cfg.Services.Transaction,
		Alert:       cfg.Services.Alert,
		Case:        cfg.Services.Case,
		Analytics:   cfg.Services.Analytics,
		Blockchain:  cfg.Services.Blockchain,
	}, log)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
	}

	// -------------------------------------------------------------------------
	// Health check aggregation handler
	// -------------------------------------------------------------------------
	healthHandler := health.Handler(health.ServiceAddrs{
		"iam":         cfg.Services.IAM,
		"kyc":         cfg.Services.KYC,
		"transaction": cfg.Services.Transaction,
		"alert":       cfg.Services.Alert,
		"case":        cfg.Services.Case,
		"analytics":   cfg.Services.Analytics,
		"blockchain":  cfg.Services.Blockchain,
	})

	// -------------------------------------------------------------------------
	// HTTP mux — register local endpoints before the catch-all proxy
	// -------------------------------------------------------------------------
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.Handle("GET /metrics", metrics.Handler())
	mux.Handle("/", router) // catch-all → reverse proxy

	// -------------------------------------------------------------------------
	// Middleware chain
	// Execution order (outermost → innermost):
	//   RequestID → Tracing → Security → Logging → CORS → RateLimit → Auth
	// -------------------------------------------------------------------------
	handler := middleware.Chain(mux,
		middleware.RequestID,
		middleware.Tracing,
		middleware.Security,
		middleware.Logging,
		middleware.CORS(cfg.CORSAllowedOrigins),
		middleware.RateLimit(cfg.PublicRPM, cfg.ServiceRPM),
		middleware.Auth(iamClient, cfg.TokenCacheBuffer, log),
	)

	// -------------------------------------------------------------------------
	// HTTP server
	// -------------------------------------------------------------------------
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// -------------------------------------------------------------------------
	// Signal handling & graceful shutdown
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srvErr := make(chan error, 1)
	go func() {
		log.Info().Str("addr", srv.Addr).Msg("API Gateway listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			srvErr <- fmt.Errorf("http listen: %w", err)
		}
		close(srvErr)
	}()

	select {
	case err := <-srvErr:
		return err
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	log.Info().Msg("API Gateway stopped")
	return nil
}
