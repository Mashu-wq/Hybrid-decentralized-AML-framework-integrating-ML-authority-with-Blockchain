// config/config.go
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Application
	Env      string
	Port     string
	Host     string
	
	// Database
	DatabaseURL        string
	DBMaxOpenConns     int
	DBMaxIdleConns     int
	DBConnMaxLifetime  time.Duration
	
	// Redis
	RedisURL      string
	RedisPassword string
	RedisDB       int
	
	// JWT
	JWTSecret     string
	JWTExpiry     int
	RefreshExpiry int
	
	// Security
	RateLimit             int
	BurstLimit            int
	PasswordMinLength     int
	PasswordMaxAgeDays    int
	MaxFailedAttempts     int
	AccountLockoutMinutes int
	
	// MFA
	MFAClaimer        string
	MFABackupCodesCount int
	
	// CORS
	AllowedOrigins   []string
	AllowCredentials bool
	
	// Email
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPFromName string
	
	// Logging
	LogLevel  string
	LogFormat string
	
	// Elasticsearch
	ElasticsearchURL      string
	ElasticsearchIndex    string
	ElasticsearchUsername string
	ElasticsearchPassword string
	
	// Sessions
	SessionExpiry        int
	SessionCleanupInterval int
	
	// API
	APIPrefix string
	APITimeout time.Duration
	
	// Feature Flags
	FeatureMFA               bool
	FeatureRateLimiting      bool
	FeatureAuditLogging      bool
	FeatureEmailNotifications bool
	
	// Thesis Specific
	ThesisMode               bool
	ThesisExperimentalFeatures bool
	ThesisLogLevel           string
	
	// Advanced Features
	EnableBehavioralBiometrics bool
	EnableRiskBasedAuth        bool
	EnableQuantumResistantAlgos bool
	
	// Demo Mode
	DemoMode        bool
	DemoUserPassword string
}

func Load() *Config {
	// Load .env file if it exists
	godotenv.Load()
	
	return &Config{
		// Application
		Env:  getEnv("ENV", "development"),
		Port: getEnv("PORT", "8080"),
		Host: getEnv("HOST", "0.0.0.0"),
		
		// Database
		DatabaseURL: getEnv("DATABASE_URL", "postgres://iam_user:password@localhost:5432/iam_service?sslmode=disable"),
		DBMaxOpenConns: getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns: getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
		DBConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		
		// Redis
		RedisURL:      getEnv("REDIS_URL", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvAsInt("REDIS_DB", 0),
		
		// JWT
		JWTSecret:     getEnv("JWT_SECRET", "your-super-secret-jwt-key-minimum-32-characters-long-change-in-production"),
		JWTExpiry:     getEnvAsInt("JWT_EXPIRY", 900),
		RefreshExpiry: getEnvAsInt("REFRESH_EXPIRY", 604800),
		
		// Security
		RateLimit:             getEnvAsInt("RATE_LIMIT", 100),
		BurstLimit:            getEnvAsInt("BURST_LIMIT", 200),
		PasswordMinLength:     getEnvAsInt("PASSWORD_MIN_LENGTH", 12),
		PasswordMaxAgeDays:    getEnvAsInt("PASSWORD_MAX_AGE_DAYS", 90),
		MaxFailedAttempts:     getEnvAsInt("MAX_FAILED_ATTEMPTS", 5),
		AccountLockoutMinutes: getEnvAsInt("ACCOUNT_LOCKOUT_MINUTES", 30),
		
		// MFA
		MFAClaimer:         getEnv("MFA_ISSUER", "IAM-Service"),
		MFABackupCodesCount: getEnvAsInt("MFA_BACKUP_CODES_COUNT", 8),
		
		// CORS
		AllowedOrigins:   getEnvAsSlice("ALLOWED_ORIGINS", []string{"*"}),
		AllowCredentials: getEnvAsBool("ALLOW_CREDENTIALS", true),
		
		// Email
		SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 587),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@iam-service.com"),
		SMTPFromName: getEnv("SMTP_FROM_NAME", "IAM Service"),
		
		// Logging
		LogLevel:  getEnv("LOG_LEVEL", "info"),
		LogFormat: getEnv("LOG_FORMAT", "json"),
		
		// Elasticsearch
		ElasticsearchURL:      getEnv("ELASTICSEARCH_URL", ""),
		ElasticsearchIndex:    getEnv("ELASTICSEARCH_INDEX", "iam-audit-logs"),
		ElasticsearchUsername: getEnv("ELASTICSEARCH_USERNAME", ""),
		ElasticsearchPassword: getEnv("ELASTICSEARCH_PASSWORD", ""),
		
		// Sessions
		SessionExpiry:        getEnvAsInt("SESSION_EXPIRY", 86400),
		SessionCleanupInterval: getEnvAsInt("SESSION_CLEANUP_INTERVAL", 3600),
		
		// API
		APIPrefix: getEnv("API_PREFIX", "/api/v1"),
		APITimeout: getEnvAsDuration("API_TIMEOUT", 30*time.Second),
		
		// Feature Flags
		FeatureMFA:               getEnvAsBool("FEATURE_MFA", true),
		FeatureRateLimiting:      getEnvAsBool("FEATURE_RATE_LIMITING", true),
		FeatureAuditLogging:      getEnvAsBool("FEATURE_AUDIT_LOGGING", true),
		FeatureEmailNotifications: getEnvAsBool("FEATURE_EMAIL_NOTIFICATIONS", false),
		
		// Thesis Specific
		ThesisMode:               getEnvAsBool("THESIS_MODE", true),
		ThesisExperimentalFeatures: getEnvAsBool("THESIS_EXPERIMENTAL_FEATURES", false),
		ThesisLogLevel:           getEnv("THESIS_LOG_LEVEL", "debug"),
		
		// Advanced Features
		EnableBehavioralBiometrics: getEnvAsBool("ENABLE_BEHAVIORAL_BIOMETRICS", false),
		EnableRiskBasedAuth:        getEnvAsBool("ENABLE_RISK_BASED_AUTH", false),
		EnableQuantumResistantAlgos: getEnvAsBool("ENABLE_QUANTUM_RESISTANT_ALGOS", false),
		
		// Demo Mode
		DemoMode:        getEnvAsBool("DEMO_MODE", false),
		DemoUserPassword: getEnv("DEMO_USER_PASSWORD", "DemoPass123!@#"),
	}
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if dur, err := time.ParseDuration(value); err == nil {
			return dur
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		if value == "" {
			return defaultValue
		}
		return strings.Split(value, ",")
	}
	return defaultValue
}