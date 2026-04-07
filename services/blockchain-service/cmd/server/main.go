package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	appfabric "github.com/fraud-detection/blockchain-service/internal/fabric"
	apphttp "github.com/fraud-detection/blockchain-service/internal/http"
	appkafka "github.com/fraud-detection/blockchain-service/internal/kafka"
	appservice "github.com/fraud-detection/blockchain-service/internal/service"
	"github.com/fraud-detection/shared/logger"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := appconfig.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := logger.Init(logger.Config{
		Level:       cfg.LogLevel,
		ServiceName: cfg.ServiceName,
		Environment: cfg.Environment,
		Pretty:      cfg.Environment == "development",
	})

	publisher := appkafka.NewPublisher(cfg.KafkaBrokers, cfg.KafkaTopic, log)
	defer publisher.Close()

	gateway, err := appfabric.New(cfg, publisher, log)
	if err != nil {
		return fmt.Errorf("create fabric gateway: %w", err)
	}
	defer gateway.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := gateway.StartEventListeners(ctx); err != nil {
		return fmt.Errorf("start event listeners: %w", err)
	}

	svc := appservice.New(cfg, gateway)
	handler := apphttp.NewHandler(svc, log)
	server := apphttp.NewServer(cfg, handler, log)

	log.Info().
		Int("http_port", cfg.HTTPPort).
		Str("connection_profile", cfg.ConnectionProfile).
		Str("org_name", cfg.OrgName).
		Msg("blockchain service ready")

	return server.Run(ctx)
}
