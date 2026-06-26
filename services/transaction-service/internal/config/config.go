// Package config loads Transaction Monitoring Service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// Config holds all Transaction Monitoring Service configuration.
type Config struct {
	// --- Service identity ---
	ServiceName string
	Environment string
	LogLevel    string
	GRPCPort    int

	// --- Kafka ---
	KafkaBrokers          []string
	TransactionsRawTopic  string // consumer: transactions.raw
	AlertsCreatedTopic    string // producer: alerts.created
	KYCEventsTopic        string // consumer: kyc.events (customer risk profile cache)
	ConsumerGroupID       string
	KYCConsumerGroupID    string
	KafkaDialTimeout      int // seconds
	KafkaWorkers          int // parallel message processors

	// --- MongoDB ---
	MongoURI        string
	MongoDB         string
	MongoCollection string // time-series collection for enriched transactions

	// --- Redis ---
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPoolSize int

	// --- ML Service ---
	MLServiceAddr    string
	MLServiceTimeout int // seconds — prediction call timeout

	// --- Downstream gRPC ---
	IAMServiceAddr string // for JWT validation

	// --- Thresholds ---
	// Alert thresholds are stratified by customer KYC risk level (FATF risk-based approach).
	// Higher-risk customers are monitored with a lower threshold (higher recall).
	AlertThresholdLow      float64 // LOW-risk customers    (default 0.70)
	AlertThresholdMedium   float64 // MEDIUM-risk customers (default 0.55)
	AlertThresholdHigh     float64 // HIGH-risk customers   (default 0.40)
	AlertThresholdCritical float64 // CRITICAL-risk customers (default 0.25)
	VelocityAlert1HLimit   int     // alert if tx count in 1h exceeds this (default 20)
	VelocityAlert24HLimit  int     // alert if tx count in 24h exceeds this (default 100)

	// --- HTTP health server ---
	HTTPPort int

	// --- Observability ---
	JaegerEndpoint string
	JWTSecret      string // shared HMAC secret for inter-service auth

	// --- Feature pipeline ---
	PipelineVersion string // semantic version of feature pipeline, e.g. "1.0.0"

	// --- Blockchain Service ---
	BlockchainServiceAddr string // HTTP base URL for blockchain-service audit endpoint
}

// Load reads configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "transaction-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		GRPCPort:    envInt("TRANSACTION_SERVICE_GRPC_PORT", 50062),

		KafkaBrokers:         envStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		TransactionsRawTopic: env("TRANSACTIONS_RAW_TOPIC", "transactions.raw"),
		AlertsCreatedTopic:   env("ALERTS_CREATED_TOPIC", "alerts.created"),
		KYCEventsTopic:       env("KAFKA_TOPIC_KYC_EVENTS", "kyc.events"),
		ConsumerGroupID:      env("KAFKA_CONSUMER_GROUP", "transaction-service-cg"),
		KYCConsumerGroupID:   env("KAFKA_KYC_CONSUMER_GROUP", "transaction-service-kyc-cg"),
		KafkaDialTimeout:     envInt("KAFKA_DIAL_TIMEOUT_SEC", 30),
		KafkaWorkers:         envInt("KAFKA_WORKERS", 8),

		MongoURI:        env("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:         env("MONGO_DB", "fraud_detection"),
		MongoCollection: env("MONGO_TX_COLLECTION", "enriched_transactions"),

		RedisAddr:     env("REDIS_ADDR", "localhost:6379"),
		RedisPassword: env("REDIS_PASSWORD", ""),
		RedisDB:       envInt("REDIS_DB", 0),
		RedisPoolSize: envInt("REDIS_POOL_SIZE", 20),

		MLServiceAddr:    env("ML_SERVICE_ADDR", "localhost:50065"),
		MLServiceTimeout: envInt("ML_SERVICE_TIMEOUT_SEC", 5),

		IAMServiceAddr: env("IAM_SERVICE_ADDR", "localhost:50060"),

		AlertThresholdLow:      envFloat("FRAUD_ALERT_THRESHOLD_LOW",      0.70),
		AlertThresholdMedium:   envFloat("FRAUD_ALERT_THRESHOLD_MEDIUM",   0.55),
		AlertThresholdHigh:     envFloat("FRAUD_ALERT_THRESHOLD_HIGH",     0.40),
		AlertThresholdCritical: envFloat("FRAUD_ALERT_THRESHOLD_CRITICAL", 0.25),
		VelocityAlert1HLimit:   envInt("VELOCITY_ALERT_1H_LIMIT", 20),
		VelocityAlert24HLimit:  envInt("VELOCITY_ALERT_24H_LIMIT", 100),

		HTTPPort:        envInt("TX_SERVICE_PORT", 9002),
		JaegerEndpoint:  env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		JWTSecret:       envRequired("INTERNAL_JWT_SECRET"),
		PipelineVersion: env("PIPELINE_VERSION", "1.0.0"),

		BlockchainServiceAddr: env("BLOCKCHAIN_SERVICE_ADDR", "http://localhost:8095"),
	}

	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("INTERNAL_JWT_SECRET is required")
	}
	thresholds := map[string]float64{
		"FRAUD_ALERT_THRESHOLD_LOW":      cfg.AlertThresholdLow,
		"FRAUD_ALERT_THRESHOLD_MEDIUM":   cfg.AlertThresholdMedium,
		"FRAUD_ALERT_THRESHOLD_HIGH":     cfg.AlertThresholdHigh,
		"FRAUD_ALERT_THRESHOLD_CRITICAL": cfg.AlertThresholdCritical,
	}
	for name, v := range thresholds {
		if v <= 0 || v >= 1 {
			return nil, fmt.Errorf("%s must be between 0 and 1, got %.2f", name, v)
		}
	}

	log.Info().
		Str("service", cfg.ServiceName).
		Str("env", cfg.Environment).
		Int("grpc_port", cfg.GRPCPort).
		Str("consumer_group", cfg.ConsumerGroupID).
		Str("raw_topic", cfg.TransactionsRawTopic).
		Str("alert_topic", cfg.AlertsCreatedTopic).
		Float64("threshold_low",      cfg.AlertThresholdLow).
		Float64("threshold_medium",   cfg.AlertThresholdMedium).
		Float64("threshold_high",     cfg.AlertThresholdHigh).
		Float64("threshold_critical", cfg.AlertThresholdCritical).
		Int("kafka_workers", cfg.KafkaWorkers).
		Msg("configuration loaded")

	return cfg, nil
}

// --- helpers ---

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
