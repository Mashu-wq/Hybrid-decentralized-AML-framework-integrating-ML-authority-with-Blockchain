// Package main is the entry point for the Case Management Service.
//
// Startup order:
//  1. Load configuration from environment variables
//  2. Initialise structured logger (zerolog)
//  3. Initialise OpenTelemetry tracing (Jaeger)
//  4. Connect to PostgreSQL (case lifecycle persistence)
//  5. Initialise AWS S3 evidence store
//  6. Initialise Blockchain Service HTTP client
//  7. Wire SAR PDF generator and CaseService
//  8. Start Kafka consumer (alerts.created → auto case creation)
//  9. Start gRPC server
// 10. Start HTTP/REST server
// 11. Wait for OS signal → graceful shutdown
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fraud-detection/case-service/internal/clients"
	"github.com/fraud-detection/case-service/internal/config"
	"github.com/fraud-detection/case-service/internal/domain"
	grpcserver "github.com/fraud-detection/case-service/internal/grpc"
	httpserver "github.com/fraud-detection/case-service/internal/http"
	casekafka "github.com/fraud-detection/case-service/internal/kafka"
	"github.com/fraud-detection/case-service/internal/pdf"
	pgRepo "github.com/fraud-detection/case-service/internal/repository/postgres"
	s3store "github.com/fraud-detection/case-service/internal/s3"
	"github.com/fraud-detection/case-service/internal/service"
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
	log.Info().Msg("case-service starting")

	// -------------------------------------------------------------------------
	// 3. OpenTelemetry tracing
	// -------------------------------------------------------------------------
	ctx := context.Background()
	if cfg.JaegerEndpoint != "" {
		tp, tracerErr := tracing.Init(ctx, tracing.Config{
			ServiceName: cfg.ServiceName,
			Environment: cfg.Environment,
			JaegerURL:   cfg.JaegerEndpoint,
		})
		if tracerErr != nil {
			log.Warn().Err(tracerErr).Msg("tracing init failed — continuing without traces")
		} else {
			defer func() { _ = tp.Shutdown(ctx) }()
		}
	}

	// -------------------------------------------------------------------------
	// 4. PostgreSQL
	// -------------------------------------------------------------------------
	pgCtx, pgCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pgCancel()

	pgPool, err := pgRepo.Connect(pgCtx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pgPool.Close()
	log.Info().Str("host", cfg.PostgresHost).Msg("PostgreSQL connected")

	caseStore := pgRepo.New(pgPool)

	// -------------------------------------------------------------------------
	// 5. AWS S3 evidence store
	// -------------------------------------------------------------------------
	s3Ctx, s3Cancel := context.WithTimeout(ctx, 10*time.Second)
	defer s3Cancel()

	evidenceStore, err := s3store.New(
		s3Ctx,
		cfg.AWSRegion,
		cfg.S3Bucket,
		cfg.AWSAccessKeyID,
		cfg.AWSSecretAccessKey,
		cfg.S3PresignTTL,
	)
	if err != nil {
		return fmt.Errorf("init S3 evidence store: %w", err)
	}
	log.Info().Str("bucket", cfg.S3Bucket).Str("region", cfg.AWSRegion).Msg("S3 evidence store configured")

	// -------------------------------------------------------------------------
	// 6. Blockchain Service HTTP client
	// -------------------------------------------------------------------------
	blockchainClient := clients.NewBlockchainClient(cfg.BlockchainServiceURL)
	{
		pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
		defer pingCancel()
		if err := blockchainClient.Ping(pingCtx); err != nil {
			log.Warn().Err(err).Str("url", cfg.BlockchainServiceURL).
				Msg("blockchain service unreachable at startup — audit trail may be incomplete")
		} else {
			log.Info().Str("url", cfg.BlockchainServiceURL).Msg("blockchain service reachable")
		}
	}

	// -------------------------------------------------------------------------
	// 7. SAR generator + CaseService
	// -------------------------------------------------------------------------
	sarGen := pdf.NewGenerator("AML Fraud Detection System", "Compliance Division")

	caseSvc := service.New(
		caseStore,
		evidenceStore,
		blockchainClient,
		sarGen,
		cfg.S3Bucket,
		cfg.Investigators,
		cfg.SARThreshold,
	)

	// -------------------------------------------------------------------------
	// 8. Kafka consumer (alerts.created → auto case creation)
	// -------------------------------------------------------------------------
	// Processor: only create cases for HIGH/CRITICAL (filtered inside consumer)
	processor := func(ctx context.Context, event *domain.AlertEvent) error {
		return caseSvc.CreateCaseFromAlert(ctx, event)
	}
	consumer := casekafka.NewConsumer(
		cfg.KafkaBrokers,
		cfg.AlertsCreatedTopic,
		cfg.ConsumerGroupID,
		cfg.KafkaWorkers,
		cfg.KafkaDialTimeout,
		processor,
	)

	// -------------------------------------------------------------------------
	// 9. gRPC server
	// -------------------------------------------------------------------------
	grpcSrv := grpcserver.New(caseSvc, log, cfg.JWTSecret)

	// -------------------------------------------------------------------------
	// 10. HTTP server
	// -------------------------------------------------------------------------
	httpHandler := httpserver.NewHandler(caseSvc)
	httpSrv := httpserver.NewServer(httpHandler, cfg.HTTPPort)

	// -------------------------------------------------------------------------
	// 11. Graceful shutdown orchestration
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 3)

	go func() {
		log.Info().
			Str("topic", cfg.AlertsCreatedTopic).
			Str("group", cfg.ConsumerGroupID).
			Int("workers", cfg.KafkaWorkers).
			Msg("Kafka consumer starting")
		if err := consumer.Run(ctx); err != nil {
			errCh <- fmt.Errorf("kafka consumer: %w", err)
		}
	}()

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

	log.Info().
		Int("http_port", cfg.HTTPPort).
		Int("grpc_port", cfg.GRPCPort).
		Str("s3_bucket", cfg.S3Bucket).
		Float64("sar_threshold", cfg.SARThreshold).
		Int("investigators", len(cfg.Investigators)).
		Msg("case-service ready")

	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received — draining")
	case fatalErr := <-errCh:
		log.Error().Err(fatalErr).Msg("fatal error — initiating shutdown")
		stop()
	}

	log.Info().Msg("case-service stopped cleanly")
	return nil
}
