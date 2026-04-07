// Package config loads Alert Service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all Alert Service configuration.
type Config struct {
	// --- Service identity ---
	ServiceName string
	Environment string
	LogLevel    string
	HTTPPort    int

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
	RedisPoolSize int

	// --- Kafka ---
	KafkaBrokers       []string
	AlertsCreatedTopic string // consumer: alerts.created
	ConsumerGroupID    string
	KafkaDialTimeout   int
	KafkaWorkers       int

	// --- Notifications ---
	// SendGrid
	SendGridAPIKey string
	EmailFrom      string
	EmailFromName  string
	DefaultEmailTo []string // default CRITICAL/HIGH alert recipients

	// Twilio SMS
	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFromPhone  string
	DefaultSMSTo     []string // default CRITICAL alert SMS recipients

	// Slack
	SlackWebhookURL string
	SlackChannel    string

	// Webhook
	WebhookURLs   []string // comma-separated custom webhook endpoints
	WebhookSecret string   // HMAC-SHA256 key for webhook signature

	// --- Escalation ---
	EscalationInterval  time.Duration // how often to check for unescalated alerts (default 1m)
	EscalationThreshold time.Duration // escalate if CRITICAL+OPEN for > this (default 15m)
	SeniorAnalysts      []string      // user IDs of senior analysts for round-robin assignment

	// --- Observability ---
	JaegerEndpoint string
	JWTSecret      string // shared HMAC secret for inter-service JWT validation

	// --- WebSocket ---
	WSPingInterval time.Duration // heartbeat interval (default 30s)
	WSWriteTimeout time.Duration // write deadline per client (default 10s)
}

// Load reads configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName: env("SERVICE_NAME", "alert-service"),
		Environment: env("ENVIRONMENT", "development"),
		LogLevel:    env("LOG_LEVEL", "info"),
		HTTPPort:    envInt("ALERT_SERVICE_PORT", 9003),

		PostgresHost:    env("POSTGRES_HOST", "localhost"),
		PostgresPort:    envInt("POSTGRES_PORT", 5432),
		PostgresDB:      env("POSTGRES_DB", "fraud_detection"),
		PostgresUser:    env("POSTGRES_USER", "fraud_user"),
		PostgresPass:    envRequired("POSTGRES_PASSWORD"),
		PostgresSSL:     env("POSTGRES_SSL_MODE", "disable"),
		PostgresMaxConn: envInt("POSTGRES_MAX_CONN", 20),
		PostgresMinConn: envInt("POSTGRES_MIN_CONN", 2),

		RedisAddr:     env("REDIS_ADDR", "localhost:6379"),
		RedisPassword: env("REDIS_PASSWORD", ""),
		RedisDB:       envInt("REDIS_DB", 0),
		RedisPoolSize: envInt("REDIS_POOL_SIZE", 10),

		KafkaBrokers:       envStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		AlertsCreatedTopic: env("ALERTS_CREATED_TOPIC", "alerts.created"),
		ConsumerGroupID:    env("KAFKA_CONSUMER_GROUP", "alert-service-cg"),
		KafkaDialTimeout:   envInt("KAFKA_DIAL_TIMEOUT_SEC", 30),
		KafkaWorkers:       envInt("KAFKA_WORKERS", 4),

		// Notifications
		SendGridAPIKey: env("SENDGRID_API_KEY", ""),
		EmailFrom:      env("EMAIL_FROM", "alerts@fraud-detection.internal"),
		EmailFromName:  env("EMAIL_FROM_NAME", "Fraud Detection System"),
		DefaultEmailTo: envStringSlice("DEFAULT_EMAIL_RECIPIENTS", nil),

		TwilioAccountSID: env("TWILIO_ACCOUNT_SID", ""),
		TwilioAuthToken:  env("TWILIO_AUTH_TOKEN", ""),
		TwilioFromPhone:  env("TWILIO_FROM_PHONE", ""),
		DefaultSMSTo:     envStringSlice("DEFAULT_SMS_RECIPIENTS", nil),

		SlackWebhookURL: env("SLACK_WEBHOOK_URL", ""),
		SlackChannel:    env("SLACK_CHANNEL", "#fraud-alerts"),

		WebhookURLs:   envStringSlice("WEBHOOK_URLS", nil),
		WebhookSecret: env("WEBHOOK_SECRET", ""),

		// Escalation
		EscalationInterval:  envDuration("ESCALATION_CHECK_INTERVAL", time.Minute),
		EscalationThreshold: envDuration("ESCALATION_THRESHOLD", 15*time.Minute),
		SeniorAnalysts:      envStringSlice("SENIOR_ANALYSTS", nil),

		JaegerEndpoint: env("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		JWTSecret:      envRequired("INTERNAL_JWT_SECRET"),

		WSPingInterval: envDuration("WS_PING_INTERVAL", 30*time.Second),
		WSWriteTimeout: envDuration("WS_WRITE_TIMEOUT", 10*time.Second),
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
		Str("topic", cfg.AlertsCreatedTopic).
		Dur("escalation_threshold", cfg.EscalationThreshold).
		Int("senior_analysts", len(cfg.SeniorAnalysts)).
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
