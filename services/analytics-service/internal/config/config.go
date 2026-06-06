// Package config loads Analytics Service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all Analytics Service configuration.
type Config struct {
	ServiceName string
	Environment string
	LogLevel    string
	GRPCPort    int
	HTTPPort    int

	// PostgreSQL (reads from fraud_alerts, investigation_cases)
	PostgresDSN     string
	PostgresHost    string
	PostgresPort    int
	PostgresDB      string
	PostgresUser    string
	PostgresPass    string
	PostgresSSL     string
	PostgresMaxConn int
	PostgresMinConn int

	// MongoDB (reads from enriched_transactions)
	MongoURI        string
	MongoDB         string
	MongoCollection string // enriched_transactions

	// Observability
	JaegerEndpoint string

	// JWT for inter-service calls
	JWTSecret string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "analytics-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		GRPCPort:    envInt("ANALYTICS_GRPC_PORT", 9008),
		HTTPPort:    envInt("ANALYTICS_SERVICE_PORT", 9006),

		PostgresHost:    env("POSTGRES_HOST", "localhost"),
		PostgresPort:    envInt("POSTGRES_PORT", 5432),
		PostgresDB:      env("POSTGRES_DB", "fraud_detection"),
		PostgresUser:    env("POSTGRES_USER", "fraud_user"),
		PostgresPass:    envRequired("POSTGRES_PASSWORD"),
		PostgresSSL:     env("POSTGRES_SSL_MODE", "disable"),
		PostgresMaxConn: envInt("POSTGRES_MAX_CONN", 10),
		PostgresMinConn: envInt("POSTGRES_MIN_CONN", 1),

		MongoURI:        env("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:         env("MONGO_DB", "fraud_detection"),
		MongoCollection: env("MONGO_COLLECTION", "enriched_transactions"),

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

	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envRequired(key string) string {
	return os.Getenv(key)
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
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

// suppress unused warning — envStringSlice is available for future config fields
var _ = envStringSlice
