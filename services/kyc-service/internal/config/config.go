// Package config loads KYC service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// Config holds all KYC service configuration.
type Config struct {
	// --- Service ---
	ServiceName string
	Environment string
	LogLevel    string
	HTTPPort    int
	GRPCPort    int

	// --- PostgreSQL ---
	PostgresDSN     string
	PostgresHost    string
	PostgresPort    int
	PostgresDB      string
	PostgresUser    string
	PostgresPass    string
	PostgresSSL     string
	PostgresMaxConn int
	PostgresMinConn int

	// --- Kafka ---
	KafkaBrokers    []string
	KYCEventsTopic  string
	WriterBatchSize int

	// --- Downstream services ---
	EncryptionServiceAddr string
	BlockchainServiceAddr string

	// --- Local document upload support ---
	DocumentUploadDir  string
	MaxUploadSizeBytes int64

	// --- Observability ---
	JaegerEndpoint string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "kyc-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		HTTPPort:    envInt("KYC_SERVICE_PORT", 9001),
		GRPCPort:    envInt("KYC_SERVICE_GRPC_PORT", 50061),

		PostgresHost:    env("POSTGRES_HOST", "localhost"),
		PostgresPort:    envInt("POSTGRES_PORT", 5432),
		PostgresDB:      env("POSTGRES_DB", "fraud_detection"),
		PostgresUser:    env("POSTGRES_USER", "fraud_user"),
		PostgresPass:    envRequired("POSTGRES_PASSWORD"),
		PostgresSSL:     env("POSTGRES_SSL_MODE", "disable"),
		PostgresMaxConn: envInt("POSTGRES_MAX_CONN", 20),
		PostgresMinConn: envInt("POSTGRES_MIN_CONN", 2),

		KafkaBrokers:    envStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		KYCEventsTopic:  env("KYC_EVENTS_TOPIC", "kyc.events"),
		WriterBatchSize: envInt("KAFKA_WRITER_BATCH_SIZE", 10),

		EncryptionServiceAddr: env("ENCRYPTION_SERVICE_ADDR", "localhost:50064"),
		BlockchainServiceAddr: env("BLOCKCHAIN_SERVICE_ADDR", "localhost:9005"),

		DocumentUploadDir:  env("DOCUMENT_UPLOAD_DIR", "tmp/kyc-uploads"),
		MaxUploadSizeBytes: envInt64("MAX_UPLOAD_SIZE_BYTES", 10<<20),

		JaegerEndpoint: env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
	}

	if cfg.PostgresPass == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
	}

	cfg.PostgresDSN = fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s pool_max_conns=%d pool_min_conns=%d",
		cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresDB,
		cfg.PostgresUser, cfg.PostgresPass, cfg.PostgresSSL,
		cfg.PostgresMaxConn, cfg.PostgresMinConn,
	)

	log.Info().
		Str("service", cfg.ServiceName).
		Str("env", cfg.Environment).
		Int("http_port", cfg.HTTPPort).
		Int("grpc_port", cfg.GRPCPort).
		Str("blockchain_addr", cfg.BlockchainServiceAddr).
		Str("document_upload_dir", cfg.DocumentUploadDir).
		Msg("configuration loaded")

	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Warn().Str("key", key).Msg("required env var not set")
	}
	return v
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return def
}

func envStringSlice(key string, def []string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				result = append(result, t)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return def
}
