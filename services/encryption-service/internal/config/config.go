// Package config loads encryption service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog/log"
)

// Config holds all encryption service configuration.
type Config struct {
	// --- Service ---
	ServiceName string
	Environment string
	LogLevel    string
	GRPCPort    int

	// --- Vault ---
	VaultAddr      string
	VaultToken     string // used when VaultAuthMethod == "token"
	VaultAppRoleID string // used when VaultAuthMethod == "approle"
	VaultSecretID  string // used when VaultAuthMethod == "approle"
	VaultAuthMethod string // "token" | "approle"

	// --- Transit key defaults ---
	DefaultKeyName    string
	KeyRotationPeriod string // e.g. "2160h" = 90 days

	// --- Observability ---
	JaegerEndpoint string

	// --- Limits ---
	MaxBatchSize int
}

// Load reads configuration from environment variables, applying sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName:     env("SERVICE_NAME", "encryption-service"),
		Environment:     env("ENVIRONMENT", "development"),
		LogLevel:        env("LOG_LEVEL", "info"),
		GRPCPort:        envInt("ENCRYPTION_SERVICE_GRPC_PORT", 50063),
		VaultAddr:       env("VAULT_ADDR", "http://localhost:8200"),
		VaultToken:      envRequired("VAULT_TOKEN"),
		VaultAppRoleID:  os.Getenv("VAULT_APP_ROLE_ID"),
		VaultSecretID:   os.Getenv("VAULT_SECRET_ID"),
		VaultAuthMethod: env("VAULT_AUTH_METHOD", "token"),
		DefaultKeyName:  env("VAULT_DEFAULT_KEY_NAME", "fraud-pii-key"),
		KeyRotationPeriod: env("VAULT_KEY_ROTATION_PERIOD", "2160h"),
		JaegerEndpoint:  env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		MaxBatchSize:    envInt("MAX_BATCH_SIZE", 100),
	}

	if cfg.VaultAuthMethod == "token" && cfg.VaultToken == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required when VAULT_AUTH_METHOD is 'token'")
	}
	if cfg.VaultAuthMethod == "approle" {
		if cfg.VaultAppRoleID == "" {
			return nil, fmt.Errorf("VAULT_APP_ROLE_ID is required when VAULT_AUTH_METHOD is 'approle'")
		}
		if cfg.VaultSecretID == "" {
			return nil, fmt.Errorf("VAULT_SECRET_ID is required when VAULT_AUTH_METHOD is 'approle'")
		}
	}

	log.Info().
		Str("service", cfg.ServiceName).
		Str("env", cfg.Environment).
		Int("grpc_port", cfg.GRPCPort).
		Str("vault_addr", cfg.VaultAddr).
		Str("vault_auth_method", cfg.VaultAuthMethod).
		Str("default_key_name", cfg.DefaultKeyName).
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
