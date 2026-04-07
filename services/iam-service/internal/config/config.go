// Package config loads IAM service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all IAM service configuration.
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

	// --- Redis ---
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisTLS      bool

	// --- JWT ---
	JWTSecret     string
	JWTAccessTTL  time.Duration
	JWTRefreshTTL time.Duration
	JWTIssuer     string

	// --- Security ---
	BcryptCost            int
	RateLimitMaxAttempts  int
	RateLimitLockDuration time.Duration
	MFAIssuer             string

	// --- Observability ---
	JaegerEndpoint string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "iam-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		HTTPPort:    envInt("IAM_SERVICE_PORT", 9000),
		GRPCPort:    envInt("IAM_SERVICE_GRPC_PORT", 50060),

		PostgresHost:    env("POSTGRES_HOST", "localhost"),
		PostgresPort:    envInt("POSTGRES_PORT", 5432),
		PostgresDB:      env("POSTGRES_DB", "fraud_detection"),
		PostgresUser:    env("POSTGRES_USER", "fraud_user"),
		PostgresPass:    envRequired("POSTGRES_PASSWORD"),
		PostgresSSL:     env("POSTGRES_SSL_MODE", "disable"),
		PostgresMaxConn: envInt("POSTGRES_MAX_CONN", 20),
		PostgresMinConn: envInt("POSTGRES_MIN_CONN", 2),

		RedisAddr:     fmt.Sprintf("%s:%d", env("REDIS_HOST", "localhost"), envInt("REDIS_PORT", 6379)),
		RedisPassword: envRequired("REDIS_PASSWORD"),
		RedisDB:       envInt("REDIS_DB", 0),
		RedisTLS:      envBool("REDIS_TLS", false),

		JWTSecret:     envRequired("JWT_SECRET"),
		JWTAccessTTL:  envDuration("JWT_ACCESS_TTL", 15*time.Minute),
		JWTRefreshTTL: envDuration("JWT_REFRESH_TTL", 7*24*time.Hour),
		JWTIssuer:     env("JWT_ISSUER", "fraud-detection-system"),

		BcryptCost:            envInt("BCRYPT_COST", 12),
		RateLimitMaxAttempts:  envInt("RATE_LIMIT_LOCKOUT_ATTEMPTS", 5),
		RateLimitLockDuration: envDuration("RATE_LIMIT_LOCKOUT_DURATION", 15*time.Minute),
		MFAIssuer:             env("MFA_ISSUER", "FraudDetectionSystem"),

		JaegerEndpoint: env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
	}

	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters (got %d)", len(cfg.JWTSecret))
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

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
