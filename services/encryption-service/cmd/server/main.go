// Package main is the entry point for the encryption service.
// It loads configuration, initialises all dependencies, wires them together,
// and runs the gRPC server until it receives SIGTERM or SIGINT.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fraud-detection/encryption-service/internal/config"
	encgrpc "github.com/fraud-detection/encryption-service/internal/grpc"
	"github.com/fraud-detection/encryption-service/internal/service"
	vaultpkg "github.com/fraud-detection/encryption-service/internal/vault"
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
		Int("grpc_port", cfg.GRPCPort).
		Str("vault_addr", cfg.VaultAddr).
		Msg("encryption service starting")

	// -------------------------------------------------------------------------
	// Tracing
	// -------------------------------------------------------------------------
	shutdownTracer, err := tracing.InitTracer(tracing.Config{
		ServiceName:    cfg.ServiceName,
		ServiceVersion: "1.0.0",
		Environment:    cfg.Environment,
		JaegerEndpoint: cfg.JaegerEndpoint,
		SampleRate:     1.0,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to initialise tracer — continuing without tracing")
	} else {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracer(shutCtx); err != nil {
				log.Error().Err(err).Msg("tracer shutdown error")
			}
		}()
	}

	// -------------------------------------------------------------------------
	// Vault client
	// -------------------------------------------------------------------------
	vaultClient, err := vaultpkg.New(cfg)
	if err != nil {
		return fmt.Errorf("connect to vault: %w", err)
	}
	log.Info().Str("vault_addr", cfg.VaultAddr).Msg("vault connected")

	// Ensure the default Transit key exists before we start accepting traffic.
	keyCtx, keyCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer keyCancel()
	if err := vaultClient.EnsureKeyExists(keyCtx, cfg.DefaultKeyName, cfg.KeyRotationPeriod); err != nil {
		return fmt.Errorf("ensure vault key %q: %w", cfg.DefaultKeyName, err)
	}
	log.Info().Str("key_name", cfg.DefaultKeyName).Msg("vault transit key ready")

	// -------------------------------------------------------------------------
	// Services
	// -------------------------------------------------------------------------
	encSvc := service.New(vaultClient, cfg.DefaultKeyName, cfg.MaxBatchSize, log)

	// -------------------------------------------------------------------------
	// gRPC server
	// -------------------------------------------------------------------------
	// Pass an empty jwtSecret to skip JWT validation on internal connections.
	// Set ENCRYPTION_JWT_SECRET in production to require bearer tokens.
	jwtSecret := os.Getenv("ENCRYPTION_JWT_SECRET")
	grpcSrv := encgrpc.New(encSvc, log, jwtSecret)

	// -------------------------------------------------------------------------
	// Signal handling & graceful shutdown
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- grpcSrv.Run(ctx, cfg.GRPCPort)
	}()

	log.Info().
		Int("grpc_port", cfg.GRPCPort).
		Msg("encryption service ready")

	select {
	case err := <-srvErr:
		if err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	log.Info().Msg("encryption service stopped")
	return nil
}
