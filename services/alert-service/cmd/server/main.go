// Package main is the entry point for the Alert & Notification Service.
//
// Startup order:
//  1. Load configuration from environment variables
//  2. Initialise structured logger (zerolog)
//  3. Initialise OpenTelemetry tracing (Jaeger)
//  4. Connect to PostgreSQL (alert lifecycle persistence)
//  5. Connect to Redis (deduplication)
//  6. Build notification providers (SendGrid, Twilio, Slack, Webhook)
//  7. Wire alert service, escalation scheduler
//  8. Start WebSocket hub
//  9. Start Kafka consumer (alerts.created)
// 10. Start gRPC server
// 11. Start HTTP/REST server
// 12. Wait for OS signal → graceful shutdown
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fraud-detection/alert-service/internal/config"
	"github.com/fraud-detection/alert-service/internal/escalation"
	grpcserver "github.com/fraud-detection/alert-service/internal/grpc"
	httpserver "github.com/fraud-detection/alert-service/internal/http"
	alertkafka "github.com/fraud-detection/alert-service/internal/kafka"
	"github.com/fraud-detection/alert-service/internal/notification"
	pgRepo "github.com/fraud-detection/alert-service/internal/repository/postgres"
	redisRepo "github.com/fraud-detection/alert-service/internal/repository/redis"
	"github.com/fraud-detection/alert-service/internal/service"
	alertws "github.com/fraud-detection/alert-service/internal/websocket"
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
	log.Info().Msg("alert-service starting")

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
	log.Info().Str("host", cfg.PostgresHost).Int("port", cfg.PostgresPort).Msg("PostgreSQL connected")

	alertStore := pgRepo.New(pgPool)

	// -------------------------------------------------------------------------
	// 5. Redis (deduplication)
	// -------------------------------------------------------------------------
	redisClient, err := redisRepo.Connect(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	defer func() { _ = redisClient.Close() }()
	log.Info().Str("addr", cfg.RedisAddr).Msg("Redis connected")

	dedupStore := redisRepo.NewDedup(redisClient)

	// -------------------------------------------------------------------------
	// 6. Notification providers
	// -------------------------------------------------------------------------
	var emailSender *notification.EmailSender
	if cfg.SendGridAPIKey != "" {
		emailSender = notification.NewEmailSender(
			cfg.SendGridAPIKey, cfg.EmailFrom, cfg.EmailFromName, cfg.DefaultEmailTo,
		)
		log.Info().Str("from", cfg.EmailFrom).Msg("SendGrid email provider configured")
	}

	var smsSender *notification.SMSSender
	if cfg.TwilioAccountSID != "" && cfg.TwilioAuthToken != "" {
		smsSender = notification.NewSMSSender(
			cfg.TwilioAccountSID, cfg.TwilioAuthToken, cfg.TwilioFromPhone, cfg.DefaultSMSTo,
		)
		log.Info().Str("from", cfg.TwilioFromPhone).Msg("Twilio SMS provider configured")
	}

	var slackSender *notification.SlackSender
	if cfg.SlackWebhookURL != "" {
		slackSender = notification.NewSlackSender(cfg.SlackWebhookURL, cfg.SlackChannel)
		log.Info().Str("channel", cfg.SlackChannel).Msg("Slack provider configured")
	}

	var webhookSender *notification.WebhookSender
	if len(cfg.WebhookURLs) > 0 {
		webhookSender = notification.NewWebhookSender(cfg.WebhookURLs, cfg.WebhookSecret)
		log.Info().Int("endpoints", len(cfg.WebhookURLs)).Msg("webhook provider configured")
	}

	dispatcher := notification.NewDispatcher(emailSender, smsSender, slackSender, webhookSender, alertStore)

	// -------------------------------------------------------------------------
	// 7. WebSocket hub
	// -------------------------------------------------------------------------
	hub := alertws.NewHub(cfg.WSPingInterval, cfg.WSWriteTimeout)
	go hub.Run()
	log.Info().Msg("WebSocket hub started")

	// -------------------------------------------------------------------------
	// 8. Alert service
	// -------------------------------------------------------------------------
	alertSvc := service.New(alertStore, dedupStore, dispatcher, hub)

	// -------------------------------------------------------------------------
	// 9. Escalation scheduler
	// -------------------------------------------------------------------------
	scheduler := escalation.NewScheduler(
		alertSvc,
		cfg.EscalationInterval,
		cfg.EscalationThreshold,
		cfg.SeniorAnalysts,
	)

	// -------------------------------------------------------------------------
	// 10. Kafka consumer (alerts.created)
	// -------------------------------------------------------------------------
	consumer := alertkafka.NewConsumer(
		cfg.KafkaBrokers,
		cfg.AlertsCreatedTopic,
		cfg.ConsumerGroupID,
		cfg.KafkaWorkers,
		cfg.KafkaDialTimeout,
		alertSvc.IngestAlert,
	)

	// -------------------------------------------------------------------------
	// 11. gRPC server
	// -------------------------------------------------------------------------
	grpcSrv := grpcserver.New(alertSvc, log, cfg.JWTSecret)

	// -------------------------------------------------------------------------
	// 12. HTTP server (REST + WebSocket)
	// -------------------------------------------------------------------------
	httpHandler := httpserver.NewHandler(alertSvc)
	httpSrv := httpserver.NewServer(httpHandler, hub, cfg.HTTPPort)

	// -------------------------------------------------------------------------
	// 13. Graceful shutdown orchestration
	// -------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 4)

	// Escalation scheduler
	go scheduler.Run(ctx)

	// Kafka consumer
	go func() {
		log.Info().
			Str("topic", cfg.AlertsCreatedTopic).
			Str("group", cfg.ConsumerGroupID).
			Int("workers", cfg.KafkaWorkers).
			Msg("Kafka consumer starting")
		if consumerErr := consumer.Run(ctx); consumerErr != nil {
			errCh <- fmt.Errorf("kafka consumer: %w", consumerErr)
		}
	}()

	// gRPC server (port: HTTPPort + 1000 = 9003 → gRPC on 10003, or configure separately)
	grpcPort := cfg.HTTPPort + 1000
	go func() {
		if grpcErr := grpcSrv.Run(ctx, grpcPort); grpcErr != nil {
			errCh <- fmt.Errorf("grpc server: %w", grpcErr)
		}
	}()

	// HTTP server
	go func() {
		if httpErr := httpSrv.Run(ctx); httpErr != nil {
			errCh <- fmt.Errorf("http server: %w", httpErr)
		}
	}()

	log.Info().
		Int("http_port", cfg.HTTPPort).
		Int("grpc_port", grpcPort).
		Dur("escalation_threshold", cfg.EscalationThreshold).
		Int("senior_analysts", len(cfg.SeniorAnalysts)).
		Msg("alert-service ready")

	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received — draining")
	case fatalErr := <-errCh:
		log.Error().Err(fatalErr).Msg("fatal error — initiating shutdown")
		stop()
	}

	log.Info().Msg("alert-service stopped cleanly")
	return nil
}
