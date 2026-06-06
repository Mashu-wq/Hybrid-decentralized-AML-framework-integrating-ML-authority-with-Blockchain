// Package main is the entry point for the Analytics Service.
//
// Startup order:
//  1. Load configuration
//  2. Initialise structured logger (zerolog)
//  3. Initialise OpenTelemetry tracing (Jaeger)
//  4. Connect to PostgreSQL (fraud_alerts, investigation_cases)
//  5. Connect to MongoDB (enriched_transactions)
//  6. Wire repositories → service → gRPC server
//  7. Start gRPC server in a goroutine
//  8. Wait for OS signal → graceful shutdown
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fraud-detection/analytics-service/internal/config"
	grpcserver "github.com/fraud-detection/analytics-service/internal/grpc"
	analyticshttp "github.com/fraud-detection/analytics-service/internal/http"
	mongorepo "github.com/fraud-detection/analytics-service/internal/repository/mongo"
	pgRepo "github.com/fraud-detection/analytics-service/internal/repository/postgres"
	"github.com/fraud-detection/analytics-service/internal/service"
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
	// 1. Configuration
	// -------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// -------------------------------------------------------------------------
	// 2. Logger
	// -------------------------------------------------------------------------
	log := logger.Init(logger.Config{
		Level:       cfg.LogLevel,
		ServiceName: cfg.ServiceName,
		Environment: cfg.Environment,
		Pretty:      cfg.Environment == "development",
	})
	log.Info().Msg("analytics-service starting")

	// -------------------------------------------------------------------------
	// 3. OpenTelemetry tracing
	// -------------------------------------------------------------------------
	ctx := context.Background()
	if cfg.JaegerEndpoint != "" {
		shutdown, tracerErr := tracing.InitTracer(tracing.Config{
			ServiceName:    cfg.ServiceName,
			Environment:    cfg.Environment,
			JaegerEndpoint: cfg.JaegerEndpoint,
		})
		if tracerErr != nil {
			log.Warn().Err(tracerErr).Msg("tracing init failed; continuing without traces")
		} else {
			defer func() { _ = shutdown(ctx) }()
		}
	}

	// -------------------------------------------------------------------------
	// 4. PostgreSQL
	// -------------------------------------------------------------------------
	pgCtx, pgCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pgCancel()

	pgPool, err := pgRepo.Connect(pgCtx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect PostgreSQL: %w", err)
	}
	defer pgPool.Close()
	log.Info().Str("host", cfg.PostgresHost).Str("db", cfg.PostgresDB).Msg("PostgreSQL connected")

	alertRepo := pgRepo.New(pgPool)

	// -------------------------------------------------------------------------
	// 5. MongoDB
	// -------------------------------------------------------------------------
	mongoCtx, mongoCancel := context.WithTimeout(ctx, 15*time.Second)
	defer mongoCancel()

	mongoCol, mongoClient, err := mongorepo.Connect(mongoCtx, cfg.MongoURI, cfg.MongoDB, cfg.MongoCollection)
	if err != nil {
		return fmt.Errorf("connect MongoDB: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mongoClient.Disconnect(shutCtx)
	}()
	log.Info().Str("db", cfg.MongoDB).Str("collection", cfg.MongoCollection).Msg("MongoDB connected")

	txRepo := mongorepo.New(mongoCol)

	// -------------------------------------------------------------------------
	// 6. Service wiring
	// -------------------------------------------------------------------------
	svc := service.New(alertRepo, txRepo, log)

	// -------------------------------------------------------------------------
	// 7. gRPC server + HTTP health server
	// -------------------------------------------------------------------------
	grpcSrv := grpcserver.New(svc, log, cfg.JWTSecret)
	httpSrv := analyticshttp.New(log, cfg.HTTPPort)

	// -------------------------------------------------------------------------
	// 8. Graceful shutdown orchestration
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		if err := grpcSrv.Run(ctx, cfg.GRPCPort); err != nil {
			errCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	go func() {
		if err := httpSrv.Run(ctx); err != nil {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	log.Info().Int("grpc_port", cfg.GRPCPort).Int("http_port", cfg.HTTPPort).Msg("analytics-service ready")

	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received — draining")
	case fatalErr := <-errCh:
		log.Error().Err(fatalErr).Msg("fatal error — initiating shutdown")
		stop()
	}

	log.Info().Msg("analytics-service stopped cleanly")
	return nil
}
