// Package main is the entry point for the IAM service.
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

	"github.com/fraud-detection/iam-service/internal/config"
	iamgrpc "github.com/fraud-detection/iam-service/internal/grpc"
	"github.com/fraud-detection/iam-service/internal/repository/postgres"
	redisrepo "github.com/fraud-detection/iam-service/internal/repository/redis"
	"github.com/fraud-detection/iam-service/internal/service"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/tracing"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
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
		Msg("IAM service starting")

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
	// Redis
	// -------------------------------------------------------------------------
	redisOpts := &goredis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}
	if cfg.RedisTLS {
		redisOpts.TLSConfig = nil // set real TLS config if needed
	}

	redisClient := goredis.NewClient(redisOpts)
	defer redisClient.Close()

	redisCtx, redisCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer redisCancel()
	if err := redisClient.Ping(redisCtx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	log.Info().Str("addr", cfg.RedisAddr).Msg("redis connected")

	// -------------------------------------------------------------------------
	// Repositories
	// -------------------------------------------------------------------------
	userRepo := postgres.NewUserRepo(dbPool)
	tokenRepo := redisrepo.NewTokenRepo(redisClient)

	// -------------------------------------------------------------------------
	// Services
	// -------------------------------------------------------------------------
	tokenSvc := service.NewTokenService(
		cfg.JWTSecret,
		cfg.JWTAccessTTL,
		cfg.JWTRefreshTTL,
		cfg.JWTIssuer,
		tokenRepo,
	)

	mfaSvc := service.NewMFAService(cfg.MFAIssuer)

	mfaStore := redisrepo.NewMFAChallengeAdapter(tokenRepo)

	authSvc := service.NewAuthService(
		userRepo,
		tokenSvc,
		mfaSvc,
		tokenRepo, // implements service.RateLimiter
		mfaStore,  // implements service.MFAChallengeStore
	)

	// -------------------------------------------------------------------------
	// gRPC server
	// -------------------------------------------------------------------------
	grpcSrv := iamgrpc.NewServer(authSvc, tokenSvc, log)

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
		Msg("IAM service ready")

	select {
	case err := <-srvErr:
		if err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	log.Info().Msg("IAM service stopped")
	return nil
}
