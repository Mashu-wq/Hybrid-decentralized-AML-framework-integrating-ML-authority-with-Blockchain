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

	// --- AWS ---
	AWSRegion      string
	AWSAccessKey   string
	AWSSecretKey   string
	TextractBucket string

	// --- Downstream services ---
	EncryptionServiceAddr string
	BlockchainServiceAddr string
	MLServiceAddr         string

	// --- Feature flags ---
	UseMockTextract   bool
	UseMockFaceMatch  bool
	UseStubBlockchain bool

	// --- Local document upload support ---
	DocumentUploadDir  string
	MaxUploadSizeBytes int64

	// --- Observability ---
	JaegerEndpoint string

	// --- Thresholds ---
	FaceMatchThreshold     float64
	OCRConfidenceThreshold float64
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

		AWSRegion:      env("AWS_REGION", "us-east-1"),
		AWSAccessKey:   env("AWS_ACCESS_KEY_ID", ""),
		AWSSecretKey:   env("AWS_SECRET_ACCESS_KEY", ""),
		TextractBucket: env("TEXTRACT_S3_BUCKET", "kyc-documents"),

		EncryptionServiceAddr: env("ENCRYPTION_SERVICE_ADDR", "localhost:50064"),
		BlockchainServiceAddr: env("BLOCKCHAIN_SERVICE_ADDR", "localhost:50063"),
		MLServiceAddr:         env("ML_SERVICE_ADDR", "localhost:50065"),

		// Default to mock in development; disable in production.
		UseMockTextract:   envBool("USE_MOCK_TEXTRACT", true),
		UseMockFaceMatch:  envBool("USE_MOCK_FACE_MATCH", true),
		UseStubBlockchain: envBool("USE_STUB_BLOCKCHAIN", true),

		DocumentUploadDir:  env("DOCUMENT_UPLOAD_DIR", "tmp/kyc-uploads"),
		MaxUploadSizeBytes: envInt64("MAX_UPLOAD_SIZE_BYTES", 10<<20),

		JaegerEndpoint: env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),

		FaceMatchThreshold:     envFloat("FACE_MATCH_THRESHOLD", 0.85),
		OCRConfidenceThreshold: envFloat("OCR_CONFIDENCE_THRESHOLD", 0.75),
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
		Bool("mock_textract", cfg.UseMockTextract).
		Bool("mock_face_match", cfg.UseMockFaceMatch).
		Bool("stub_blockchain", cfg.UseStubBlockchain).
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

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
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
