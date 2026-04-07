// Package config loads Case Service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all Case Service configuration.
type Config struct {
	ServiceName string
	Environment string
	LogLevel    string
	HTTPPort    int
	GRPCPort    int

	// PostgreSQL
	PostgresDSN     string
	PostgresHost    string
	PostgresPort    int
	PostgresDB      string
	PostgresUser    string
	PostgresPass    string
	PostgresSSL     string
	PostgresMaxConn int
	PostgresMinConn int

	// Kafka
	KafkaBrokers       []string
	AlertsCreatedTopic string
	ConsumerGroupID    string
	KafkaDialTimeout   int
	KafkaWorkers       int

	// AWS S3
	AWSRegion          string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	S3Bucket           string
	S3PresignTTL       time.Duration // default 15 minutes

	// Blockchain Service (internal HTTP)
	BlockchainServiceURL string

	// Investigator pool for round-robin assignment
	Investigators []string

	// SAR thresholds: auto-generate SAR when fraud_prob >= this
	SARThreshold float64

	// Observability
	JaegerEndpoint string
	JWTSecret      string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "case-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		HTTPPort:    envInt("CASE_SERVICE_PORT", 9004),
		GRPCPort:    envInt("CASE_SERVICE_GRPC_PORT", 10004),

		PostgresHost:    env("POSTGRES_HOST", "localhost"),
		PostgresPort:    envInt("POSTGRES_PORT", 5432),
		PostgresDB:      env("POSTGRES_DB", "fraud_detection"),
		PostgresUser:    env("POSTGRES_USER", "fraud_user"),
		PostgresPass:    envRequired("POSTGRES_PASSWORD"),
		PostgresSSL:     env("POSTGRES_SSL_MODE", "disable"),
		PostgresMaxConn: envInt("POSTGRES_MAX_CONN", 20),
		PostgresMinConn: envInt("POSTGRES_MIN_CONN", 2),

		KafkaBrokers:       envStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		AlertsCreatedTopic: env("ALERTS_CREATED_TOPIC", "alerts.created"),
		ConsumerGroupID:    env("KAFKA_CONSUMER_GROUP", "case-service-cg"),
		KafkaDialTimeout:   envInt("KAFKA_DIAL_TIMEOUT_SEC", 30),
		KafkaWorkers:       envInt("KAFKA_WORKERS", 4),

		AWSRegion:          env("AWS_REGION", "us-east-1"),
		AWSAccessKeyID:     env("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey: env("AWS_SECRET_ACCESS_KEY", ""),
		S3Bucket:           env("S3_EVIDENCE_BUCKET", "fraud-detection-evidence"),
		S3PresignTTL:       envDuration("S3_PRESIGN_TTL", 15*time.Minute),

		BlockchainServiceURL: env("BLOCKCHAIN_SERVICE_URL", "http://localhost:9001"),

		Investigators: envStringSlice("INVESTIGATORS", nil),
		SARThreshold:  envFloat("SAR_THRESHOLD", 0.85),

		JaegerEndpoint: env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		JWTSecret:      envRequired("INTERNAL_JWT_SECRET"),
	}

	if cfg.PostgresPass == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("INTERNAL_JWT_SECRET is required")
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
		Str("s3_bucket", cfg.S3Bucket).
		Int("investigators", len(cfg.Investigators)).
		Float64("sar_threshold", cfg.SARThreshold).
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

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
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
