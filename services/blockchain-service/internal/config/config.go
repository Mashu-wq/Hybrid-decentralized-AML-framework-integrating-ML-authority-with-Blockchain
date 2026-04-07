package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServiceName string
	Environment string
	LogLevel    string

	HTTPPort          int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ShutdownTimeout   time.Duration
	ConnectionProfile string
	OrgName           string
	Username          string
	PoolSize          int

	KYCChannel     string
	AlertChannel   string
	AuditChannel   string
	KYCChaincode   string
	AlertChaincode string
	AuditChaincode string

	KafkaBrokers []string
	KafkaTopic   string
}

func Load() (Config, error) {
	cfg := Config{
		ServiceName:       getenv("BLOCKCHAIN_SERVICE_NAME", "blockchain-service"),
		Environment:       getenv("BLOCKCHAIN_ENV", "development"),
		LogLevel:          getenv("BLOCKCHAIN_LOG_LEVEL", "info"),
		HTTPPort:          getenvInt("BLOCKCHAIN_HTTP_PORT", 8095),
		ReadTimeout:       getenvDuration("BLOCKCHAIN_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      getenvDuration("BLOCKCHAIN_HTTP_WRITE_TIMEOUT", 15*time.Second),
		ShutdownTimeout:   getenvDuration("BLOCKCHAIN_SHUTDOWN_TIMEOUT", 10*time.Second),
		ConnectionProfile: getenv("BLOCKCHAIN_CONNECTION_PROFILE", "../../blockchain/network/connection-profiles/org1.yaml"),
		OrgName:           getenv("BLOCKCHAIN_ORG_NAME", "Org1"),
		Username:          getenv("BLOCKCHAIN_USERNAME", "Admin"),
		PoolSize:          getenvInt("BLOCKCHAIN_POOL_SIZE", 4),
		KYCChannel:        getenv("BLOCKCHAIN_KYC_CHANNEL", "kyc-channel"),
		AlertChannel:      getenv("BLOCKCHAIN_ALERT_CHANNEL", "alert-channel"),
		AuditChannel:      getenv("BLOCKCHAIN_AUDIT_CHANNEL", "audit-channel"),
		KYCChaincode:      getenv("BLOCKCHAIN_KYC_CHAINCODE", "kyc-contract"),
		AlertChaincode:    getenv("BLOCKCHAIN_ALERT_CHAINCODE", "alert-contract"),
		AuditChaincode:    getenv("BLOCKCHAIN_AUDIT_CHAINCODE", "audit-contract"),
		KafkaTopic:        getenv("BLOCKCHAIN_EVENT_TOPIC", "blockchain.events"),
	}

	if raw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS")); raw != "" {
		cfg.KafkaBrokers = splitAndTrim(raw)
	}
	if cfg.ConnectionProfile == "" {
		return Config{}, fmt.Errorf("BLOCKCHAIN_CONNECTION_PROFILE is required")
	}
	if cfg.PoolSize < 1 {
		return Config{}, fmt.Errorf("BLOCKCHAIN_POOL_SIZE must be >= 1")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if value, err := time.ParseDuration(raw); err == nil {
			return value
		}
	}
	return fallback
}

func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
