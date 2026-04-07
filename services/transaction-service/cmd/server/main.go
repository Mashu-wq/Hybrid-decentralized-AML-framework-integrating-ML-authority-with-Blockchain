// Package main is the entry point for the Transaction Monitoring Service.
//
// Startup order:
//  1. Load configuration from environment variables
//  2. Initialise structured logger (zerolog)
//  3. Initialise OpenTelemetry tracing (Jaeger)
//  4. Connect to MongoDB (time-series enriched_transactions collection)
//  5. Connect to Redis (velocity tracking, risk score cache)
//  6. Dial ML Service gRPC
//  7. Create Kafka alert producer (alerts.created)
//  8. Wire feature extractor → ML client → TransactionService
//  9. Start Kafka consumer (transactions.raw) in a goroutine
// 10. Start gRPC server in a goroutine
// 11. Wait for OS signal → graceful shutdown
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fraud-detection/transaction-service/internal/clients"
	"github.com/fraud-detection/transaction-service/internal/config"
	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/fraud-detection/transaction-service/internal/features"
	grpcserver "github.com/fraud-detection/transaction-service/internal/grpc"
	txkafka "github.com/fraud-detection/transaction-service/internal/kafka"
	mongorepo "github.com/fraud-detection/transaction-service/internal/repository/mongo"
	redisrepo "github.com/fraud-detection/transaction-service/internal/repository/redis"
	"github.com/fraud-detection/transaction-service/internal/service"
	"github.com/fraud-detection/shared/grpcclient"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/tracing"
	goredis "github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	mongoopts "go.mongodb.org/mongo-driver/mongo/options"
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
	log.Info().Str("pipeline_version", cfg.PipelineVersion).Msg("transaction-service starting")

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
			log.Warn().Err(tracerErr).Msg("tracing init failed; continuing without traces")
		} else {
			defer func() { _ = tp.Shutdown(ctx) }()
		}
	}

	// -------------------------------------------------------------------------
	// 4. MongoDB
	// -------------------------------------------------------------------------
	mongoCtx, mongoCancel := context.WithTimeout(ctx, 15*time.Second)
	defer mongoCancel()

	mongoClient, err := mongo.Connect(mongoCtx, mongoopts.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		return fmt.Errorf("connect MongoDB: %w", err)
	}
	if err := mongoClient.Ping(mongoCtx, nil); err != nil {
		return fmt.Errorf("ping MongoDB %s: %w", cfg.MongoURI, err)
	}
	log.Info().Str("db", cfg.MongoDB).Str("collection", cfg.MongoCollection).Msg("MongoDB connected")

	txRepo, err := mongorepo.NewTransactionRepository(
		mongoCtx,
		mongoClient.Database(cfg.MongoDB),
		cfg.MongoCollection,
		log,
	)
	if err != nil {
		return fmt.Errorf("init transaction repository: %w", err)
	}

	// -------------------------------------------------------------------------
	// 5. Redis
	// -------------------------------------------------------------------------
	redisClient := goredis.NewClient(&goredis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
		PoolSize: cfg.RedisPoolSize,
	})
	{
		pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
		defer pingCancel()
		if err := redisClient.Ping(pingCtx).Err(); err != nil {
			return fmt.Errorf("ping Redis %s: %w", cfg.RedisAddr, err)
		}
	}
	log.Info().Str("addr", cfg.RedisAddr).Msg("Redis connected")

	velocityRepo := redisrepo.NewVelocityRepository(redisClient, log)

	// -------------------------------------------------------------------------
	// 6. ML Service gRPC
	// -------------------------------------------------------------------------
	var mlClient *clients.MLClient
	mlConn, mlErr := grpcclient.New(ctx, grpcclient.Config{
		Target:        cfg.MLServiceAddr,
		CallerService: cfg.ServiceName,
		TLS:           false, // TODO: TLS in production
		DialTimeout:   10 * time.Second,
		Log:           log,
	})
	if mlErr != nil {
		log.Warn().Err(mlErr).Str("addr", cfg.MLServiceAddr).
			Msg("ML service unavailable at startup — heuristic fallback active")
		// Pass nil conn — MLClient.PredictFraud handles nil conn gracefully via fallback
	}
	mlClient = clients.NewMLClient(mlConn, cfg.MLServiceTimeout, log)
	if mlErr == nil {
		log.Info().Str("addr", cfg.MLServiceAddr).Msg("ML service gRPC connected")
	}

	// -------------------------------------------------------------------------
	// 7. Kafka alert producer
	// -------------------------------------------------------------------------
	alertProducer := txkafka.NewAlertProducer(cfg.KafkaBrokers, cfg.AlertsCreatedTopic, log)
	defer func() {
		if closeErr := alertProducer.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("alert producer close error")
		}
	}()

	// -------------------------------------------------------------------------
	// 8. Feature extractor + service wiring
	// -------------------------------------------------------------------------
	extractor := features.NewExtractor(
		velocityRepo,
		log,
		cfg.PipelineVersion,
		cfg.VelocityAlert1HLimit,
		cfg.VelocityAlert24HLimit,
	)

	txService := service.NewTransactionService(
		extractor,
		mlClient,
		txRepo,
		velocityRepo,
		alertProducer,
		service.Config{
			AlertThreshold:   cfg.FraudAlertThreshold,
			Velocity1HLimit:  cfg.VelocityAlert1HLimit,
			Velocity24HLimit: cfg.VelocityAlert24HLimit,
		},
		log,
	)

	// -------------------------------------------------------------------------
	// 9. Kafka consumer (transactions.raw)
	// -------------------------------------------------------------------------
	// Wrap ProcessTransaction to match the kafka.MessageProcessor signature.
	processor := func(ctx context.Context, raw *domain.RawTransaction) error {
		_, err := txService.ProcessTransaction(ctx, raw)
		return err
	}

	consumer := txkafka.NewConsumer(
		cfg.KafkaBrokers,
		cfg.TransactionsRawTopic,
		cfg.ConsumerGroupID,
		cfg.KafkaWorkers,
		cfg.KafkaDialTimeout,
		processor,
		log,
	)

	// -------------------------------------------------------------------------
	// 10. gRPC server
	// -------------------------------------------------------------------------
	grpcSrv := grpcserver.New(txService, log, cfg.JWTSecret)

	// -------------------------------------------------------------------------
	// 11. Graceful shutdown orchestration
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		log.Info().
			Str("topic", cfg.TransactionsRawTopic).
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

	log.Info().
		Int("grpc_port", cfg.GRPCPort).
		Float64("alert_threshold", cfg.FraudAlertThreshold).
		Msg("transaction-service ready")

	// Block until signal or fatal error
	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received — draining")
	case fatalErr := <-errCh:
		log.Error().Err(fatalErr).Msg("fatal error — initiating shutdown")
		stop()
	}

	// Drain connections with a timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := mongoClient.Disconnect(shutdownCtx); err != nil {
		log.Warn().Err(err).Msg("MongoDB disconnect error")
	}
	if err := redisClient.Close(); err != nil {
		log.Warn().Err(err).Msg("Redis close error")
	}
	if mlConn != nil {
		if err := mlConn.Close(); err != nil {
			log.Warn().Err(err).Msg("ML gRPC connection close error")
		}
	}

	log.Info().Msg("transaction-service stopped cleanly")
	return nil
}
