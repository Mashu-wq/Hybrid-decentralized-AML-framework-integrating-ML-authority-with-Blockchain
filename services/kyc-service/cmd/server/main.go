// Package main is the entry point for the KYC service.
// It loads configuration, initialises all dependencies, wires them together,
// and runs the gRPC and HTTP servers until it receives SIGTERM or SIGINT.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/fraud-detection/kyc-service/internal/clients"
	"github.com/fraud-detection/kyc-service/internal/config"
	kycgrpc "github.com/fraud-detection/kyc-service/internal/grpc"
	kychttp "github.com/fraud-detection/kyc-service/internal/http"
	"github.com/fraud-detection/kyc-service/internal/kafka"
	"github.com/fraud-detection/kyc-service/internal/repository/postgres"
	"github.com/fraud-detection/kyc-service/internal/service"
	"github.com/fraud-detection/kyc-service/internal/storage"
	"github.com/fraud-detection/kyc-service/internal/textract"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/tracing"
	"github.com/jackc/pgx/v5/pgxpool"
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
		Int("http_port", cfg.HTTPPort).
		Int("grpc_port", cfg.GRPCPort).
		Msg("KYC service starting")

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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracer(ctx); err != nil {
				log.Error().Err(err).Msg("tracer shutdown error")
			}
		}()
	}

	// -------------------------------------------------------------------------
	// PostgreSQL
	// -------------------------------------------------------------------------
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dbCancel()

	dbPool, err := pgxpool.New(dbCtx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer dbPool.Close()

	if err := dbPool.Ping(dbCtx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	log.Info().Str("host", cfg.PostgresHost).Int("port", cfg.PostgresPort).Msg("postgres connected")

	// -------------------------------------------------------------------------
	// Encryption service client
	// -------------------------------------------------------------------------
	encClient, err := clients.NewEncryptionClient(cfg.EncryptionServiceAddr, log)
	if err != nil {
		return fmt.Errorf("connect to encryption service: %w", err)
	}
	log.Info().Str("addr", cfg.EncryptionServiceAddr).Msg("encryption service client ready")

	// -------------------------------------------------------------------------
	// Blockchain client
	// -------------------------------------------------------------------------
	var blockchainClient clients.BlockchainClient
	if cfg.UseStubBlockchain {
		blockchainClient = clients.NewStubBlockchainClient(log)
		log.Info().Msg("using stub blockchain client")
	} else {
		blockchainClient = clients.NewRemoteBlockchainClient(cfg.BlockchainServiceAddr, log)
		log.Info().Str("addr", cfg.BlockchainServiceAddr).Msg("remote blockchain client ready")
	}

	// -------------------------------------------------------------------------
	// Face match client
	// -------------------------------------------------------------------------
	var faceMatchClient clients.FaceMatchClient
	if cfg.UseMockFaceMatch {
		faceMatchClient = clients.NewMockFaceMatchClient(cfg.FaceMatchThreshold, log)
		log.Info().Msg("using mock face match client")
	} else {
		faceMatchClient, err = clients.NewMLFaceMatchClient(cfg.MLServiceAddr, log)
		if err != nil {
			return fmt.Errorf("connect to ML service for face matching: %w", err)
		}
		log.Info().Str("addr", cfg.MLServiceAddr).Msg("ML face match client ready")
	}

	// -------------------------------------------------------------------------
	// OCR client (real AWS Textract or mock based on config)
	// -------------------------------------------------------------------------
	var ocrClient textract.OCRClient
	if cfg.UseMockTextract {
		ocrClient = &textract.MockOCRClient{}
		log.Info().Msg("using mock Textract OCR client (development mode)")
	} else {
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
		)
		if err != nil {
			return fmt.Errorf("load AWS config: %w", err)
		}
		ocrClient = textract.NewTextractClient(awsCfg, cfg.TextractBucket)
		log.Info().
			Str("region", cfg.AWSRegion).
			Str("bucket", cfg.TextractBucket).
			Msg("AWS Textract client ready")
	}

	// -------------------------------------------------------------------------
	// Kafka event producer
	// -------------------------------------------------------------------------
	eventProducer := kafka.NewEventProducer(cfg.KafkaBrokers, cfg.KYCEventsTopic, log)
	defer func() {
		if err := eventProducer.Close(); err != nil {
			log.Error().Err(err).Msg("kafka producer close error")
		}
	}()
	log.Info().Strs("brokers", cfg.KafkaBrokers).Str("topic", cfg.KYCEventsTopic).Msg("kafka producer ready")

	// -------------------------------------------------------------------------
	// Repository
	// -------------------------------------------------------------------------
	kycRepo := postgres.NewKYCRepo(dbPool)
	documentStore := storage.NewLocalDocumentStore(cfg.DocumentUploadDir)

	// -------------------------------------------------------------------------
	// KYC Service
	// -------------------------------------------------------------------------
	kycSvc := service.NewKYCService(
		kycRepo,
		encClient,
		blockchainClient,
		faceMatchClient,
		ocrClient,
		eventProducer,
		log,
		cfg,
	)

	// -------------------------------------------------------------------------
	// Signal handling
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srvErr := make(chan error, 2)

	// -------------------------------------------------------------------------
	// gRPC server
	// -------------------------------------------------------------------------
	jwtSecret := os.Getenv("KYC_JWT_SECRET")
	grpcSrv := kycgrpc.New(kycSvc, log, jwtSecret)
	go func() {
		if err := grpcSrv.Run(ctx, cfg.GRPCPort); err != nil {
			srvErr <- fmt.Errorf("gRPC server: %w", err)
		}
	}()

	// -------------------------------------------------------------------------
	// HTTP server
	// -------------------------------------------------------------------------
	httpSrv := kychttp.New(kycSvc, documentStore, log, cfg.HTTPPort)
	go func() {
		if err := httpSrv.Run(ctx); err != nil {
			srvErr <- fmt.Errorf("HTTP server: %w", err)
		}
	}()

	log.Info().
		Int("grpc_port", cfg.GRPCPort).
		Int("http_port", cfg.HTTPPort).
		Msg("KYC service ready")

	select {
	case err := <-srvErr:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	log.Info().Msg("KYC service stopped")
	return nil
}
