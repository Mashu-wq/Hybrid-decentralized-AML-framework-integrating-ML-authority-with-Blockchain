// Package config loads API Gateway configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the API Gateway.
type Config struct {
	ServiceName string
	Environment string
	LogLevel    string

	// HTTP listener port.
	Port int

	// IAMServiceAddr is the gRPC address of the IAM service (for ValidateToken).
	IAMServiceAddr string

	// Downstream service HTTP base URLs.
	Services ServiceAddrs

	// CORSAllowedOrigins is the whitelist of allowed origins.
	CORSAllowedOrigins []string

	// Rate limiting — token bucket per client.
	PublicRPM  int // requests per minute for public (unauthenticated) callers
	ServiceRPM int // requests per minute for service-to-service callers

	// JaegerEndpoint is the Jaeger collector HTTP endpoint.
	JaegerEndpoint string

	// TokenCacheBuffer is how long before actual expiry we evict a cached token.
	TokenCacheBuffer time.Duration
}

// ServiceAddrs holds the HTTP base URL for each downstream service.
type ServiceAddrs struct {
	IAM         string
	KYC         string
	Transaction string
	Alert       string
	Case        string
	Analytics   string
	Blockchain  string
}

// Load reads configuration from environment variables, applying safe defaults.
func Load() (*Config, error) {
	iamHost := getEnv("IAM_SERVICE_HOST", "localhost")
	kycHost := getEnv("KYC_SERVICE_HOST", "localhost")
	txHost := getEnv("TX_SERVICE_HOST", "localhost")
	alertHost := getEnv("ALERT_SERVICE_HOST", "localhost")
	caseHost := getEnv("CASE_SERVICE_HOST", "localhost")
	analyticsHost := getEnv("ANALYTICS_SERVICE_HOST", "localhost")
	blockchainHost := getEnv("BLOCKCHAIN_SERVICE_HOST", "localhost")

	cfg := &Config{
		ServiceName:    "api-gateway",
		Environment:    getEnv("ENVIRONMENT", "development"),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
		Port:           getEnvInt("API_GATEWAY_PORT", 8080),
		IAMServiceAddr: fmt.Sprintf("%s:%s", iamHost, getEnv("IAM_SERVICE_GRPC_PORT", "50060")),
		JaegerEndpoint: getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		PublicRPM:      getEnvInt("RATE_LIMIT_PUBLIC_RPM", 100),
		ServiceRPM:     getEnvInt("RATE_LIMIT_SERVICE_RPM", 1000),
		TokenCacheBuffer: 30 * time.Second,
		Services: ServiceAddrs{
			IAM:         fmt.Sprintf("http://%s:%s", iamHost, getEnv("IAM_SERVICE_PORT", "9000")),
			KYC:         fmt.Sprintf("http://%s:%s", kycHost, getEnv("KYC_SERVICE_PORT", "9001")),
			Transaction: fmt.Sprintf("http://%s:%s", txHost, getEnv("TX_SERVICE_PORT", "9002")),
			Alert:       fmt.Sprintf("http://%s:%s", alertHost, getEnv("ALERT_SERVICE_PORT", "9003")),
			Case:        fmt.Sprintf("http://%s:%s", caseHost, getEnv("CASE_SERVICE_PORT", "9004")),
			Analytics:   fmt.Sprintf("http://%s:%s", analyticsHost, getEnv("ANALYTICS_SERVICE_PORT", "9006")),
			Blockchain:  fmt.Sprintf("http://%s:%s", blockchainHost, getEnv("BLOCKCHAIN_SERVICE_PORT", "9005")),
		},
	}

	rawOrigins := getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	for _, o := range strings.Split(rawOrigins, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			cfg.CORSAllowedOrigins = append(cfg.CORSAllowedOrigins, trimmed)
		}
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
