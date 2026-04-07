// Package domain contains the core business types for the Transaction Monitoring Service.
// These types are independent of transport (gRPC/HTTP) and storage (MongoDB/Redis) details.
package domain

import (
	"errors"
	"time"
)

// ---------------------------------------------------------------------------
// Risk level
// ---------------------------------------------------------------------------

// RiskLevel classifies the risk of a transaction or customer.
type RiskLevel int32

const (
	RiskLevelUnspecified RiskLevel = 0
	RiskLevelLow         RiskLevel = 1 // fraud_prob < 0.5
	RiskLevelMedium      RiskLevel = 2 // 0.5 – 0.7
	RiskLevelHigh        RiskLevel = 3 // 0.7 – 0.85
	RiskLevelCritical    RiskLevel = 4 // > 0.85
)

// String returns a human-readable risk level name.
func (r RiskLevel) String() string {
	switch r {
	case RiskLevelLow:
		return "LOW"
	case RiskLevelMedium:
		return "MEDIUM"
	case RiskLevelHigh:
		return "HIGH"
	case RiskLevelCritical:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// FraudProbToRiskLevel converts a [0,1] fraud probability to a RiskLevel.
func FraudProbToRiskLevel(prob float64) RiskLevel {
	switch {
	case prob >= 0.85:
		return RiskLevelCritical
	case prob >= 0.70:
		return RiskLevelHigh
	case prob >= 0.50:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// ---------------------------------------------------------------------------
// Raw transaction
// ---------------------------------------------------------------------------

// RawTransaction is the inbound transaction exactly as received from the Kafka topic.
// No enrichment has occurred yet. Fields map to the RawTransaction proto message.
type RawTransaction struct {
	TxHash              string            `json:"tx_hash" bson:"tx_hash"`
	CustomerID          string            `json:"customer_id" bson:"customer_id"`
	Amount              float64           `json:"amount" bson:"amount"`
	CurrencyCode        string            `json:"currency_code" bson:"currency_code"`
	MerchantID          string            `json:"merchant_id" bson:"merchant_id"`
	MerchantName        string            `json:"merchant_name" bson:"merchant_name"`
	MerchantCategory    string            `json:"merchant_category" bson:"merchant_category"`
	CountryCode         string            `json:"country_code" bson:"country_code"`
	Channel             string            `json:"channel" bson:"channel"`
	CounterpartyID      string            `json:"counterparty_id" bson:"counterparty_id"`
	CounterpartyCountry string            `json:"counterparty_country" bson:"counterparty_country"`
	Latitude            float64           `json:"latitude" bson:"latitude"`
	Longitude           float64           `json:"longitude" bson:"longitude"`
	TransactionAt       time.Time         `json:"transaction_at" bson:"transaction_at"`
	Metadata            map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// Validate checks required fields on a RawTransaction.
func (r *RawTransaction) Validate() error {
	if r.TxHash == "" {
		return errors.New("tx_hash is required")
	}
	if r.CustomerID == "" {
		return errors.New("customer_id is required")
	}
	if r.Amount <= 0 {
		return errors.New("amount must be positive")
	}
	if r.CurrencyCode == "" {
		return errors.New("currency_code is required")
	}
	if r.TransactionAt.IsZero() {
		return errors.New("transaction_at is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Feature vector (domain representation)
// ---------------------------------------------------------------------------

// TransactionFeatures is the complete feature vector produced by the feature extraction
// pipeline. The ML client maps this to the mlv1.TransactionFeatures proto type.
type TransactionFeatures struct {
	// Identifiers
	TxHash     string
	CustomerID string

	// Temporal
	TxHour           int
	DayOfWeek        int
	IsWeekend        bool
	TimeSinceLastTxS float64
	TxFrequency1H    float64
	TxFrequency24H   float64

	// Amount / behavioral
	Amount               float64
	CurrencyCode         string
	AmountUSDEquiv       float64
	AvgAmount7D          float64
	AvgAmount30D         float64
	StdAmount30D         float64
	AmountDeviationScore float64
	Velocity1H           float64
	Velocity24H          float64

	// Geographic
	CountryCode         string
	GeographicRiskScore float64
	CrossBorderFlag     bool
	CountryChange2H     bool
	DistanceKmFromLast  float64

	// Merchant / category
	MerchantCategory   string
	MerchantRiskScore  float64
	IsHighRiskMerchant bool

	// KYC / customer profile
	CustomerRiskScore float64
	KYCRiskLevel      int
	DaysSinceKYC      int
	TotalTxCount30D   int

	// Graph features (async — zero until GNN run completes)
	Pagerank               float64
	ClusteringCoefficient  float64
	BetweennessCentrality  float64
	LouvainCommunityID     int
	HopsToKnownFraudster   int // -1 = not reachable
	DirectFraudNeighbors   int

	// Elliptic raw features (keyed feature_1 … feature_166)
	EllipticFeatures map[string]float64
}

// ---------------------------------------------------------------------------
// SHAP contribution
// ---------------------------------------------------------------------------

// SHAPContribution holds one feature's contribution to the fraud prediction.
type SHAPContribution struct {
	FeatureName   string
	FeatureValue  float64
	SHAPValue     float64 // positive → pushes toward fraud
	AbsImportance float64
}

// ---------------------------------------------------------------------------
// Fraud prediction
// ---------------------------------------------------------------------------

// FraudPrediction is the ML service's output for a single transaction.
type FraudPrediction struct {
	FraudProbability   float64
	IsFraud            bool
	RiskLevel          RiskLevel
	ModelVersion       string
	PredictionID       string
	SHAPValues         []SHAPContribution
	ModelProbabilities map[string]float64
	BaseValue          float64
	LatencyMS          float64
	PredictedAt        time.Time
}

// ---------------------------------------------------------------------------
// Enriched transaction (stored in MongoDB)
// ---------------------------------------------------------------------------

// EnrichedTransaction is the fully processed transaction record stored in MongoDB.
// The processed_at field is used as the time-series collection's timeField.
type EnrichedTransaction struct {
	// MongoDB uses TxHash as the document _id for idempotent upserts.
	TxHash           string `json:"tx_hash" bson:"_id"`
	CustomerID       string `json:"customer_id" bson:"customer_id"` // metaField for time-series

	Raw              *RawTransaction    `json:"raw" bson:"raw"`
	Features         *TransactionFeatures `json:"features" bson:"features"`
	FraudProbability float64            `json:"fraud_probability" bson:"fraud_probability"`
	IsFraud          bool               `json:"is_fraud" bson:"is_fraud"`
	RiskLevel        RiskLevel          `json:"risk_level" bson:"risk_level"`
	ModelVersion     string             `json:"model_version" bson:"model_version"`
	PredictionID     string             `json:"prediction_id,omitempty" bson:"prediction_id,omitempty"`
	SHAPValues       []SHAPContribution `json:"shap_values,omitempty" bson:"shap_values,omitempty"`
	AlertCreated     bool               `json:"alert_created" bson:"alert_created"`
	AlertID          string             `json:"alert_id,omitempty" bson:"alert_id,omitempty"`
	ProcessedAt      time.Time          `json:"processed_at" bson:"processed_at"`
}

// ---------------------------------------------------------------------------
// Alert event (published to Kafka alerts.created)
// ---------------------------------------------------------------------------

// AlertEvent is published to the alerts.created Kafka topic when fraud_probability > threshold.
// The Alert Service (Phase 9) consumes this topic to create alert records.
type AlertEvent struct {
	AlertID              string    `json:"alert_id"`
	CustomerID           string    `json:"customer_id"`
	TxHash               string    `json:"tx_hash"`
	FraudProbability     float64   `json:"fraud_probability"`
	RiskScore            float64   `json:"risk_score"` // 0–100 normalised
	RiskLevel            string    `json:"risk_level"`
	ModelVersion         string    `json:"model_version"`
	SHAPExplanationJSON  string    `json:"shap_explanation_json,omitempty"`
	FeaturesSnapshotJSON string    `json:"features_snapshot_json,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Velocity / risk cache types
// ---------------------------------------------------------------------------

// VelocityRecord is stored in Redis sorted sets to track per-customer transaction history.
// Score = Unix timestamp (milliseconds).
type VelocityRecord struct {
	TxHash          string  `json:"h"`
	Amount          float64 `json:"a"`
	AmountUSDEquiv  float64 `json:"u"`
	CountryCode     string  `json:"c"`
	MerchantCategory string `json:"m"`
}

// VelocityStats aggregates velocity data for a customer across multiple time windows.
type VelocityStats struct {
	CustomerID           string
	TxCount1H            int
	TxCount24H           int
	TxCount7D            int
	TotalAmount1H        float64
	TotalAmount24H       float64
	TotalAmount7D        float64
	DistinctCountries24H int
	DistinctMerchants24H int
	VelocityAlert1H      bool
	VelocityAlert24H     bool
}

// CustomerProfile is cached in Redis after KYC registration.
type CustomerProfile struct {
	CustomerID  string
	RiskScore   float64
	KYCRiskLevel int
	KYCDate     time.Time
}

// CachedRiskScore is the 5-minute TTL cache entry for a customer's risk score.
type CachedRiskScore struct {
	CustomerID   string    `json:"customer_id"`
	RiskScore    float64   `json:"risk_score"`  // 0–100
	RiskLevel    RiskLevel `json:"risk_level"`
	FraudRate30D float64   `json:"fraud_rate_30d"`
	AlertCount30D int      `json:"alert_count_30d"`
	ComputedAt   time.Time `json:"computed_at"`
}

// LastTxRecord stores the last transaction per customer for temporal / geographic features.
type LastTxRecord struct {
	TxHash      string    `json:"tx_hash"`
	Amount      float64   `json:"amount"`
	CountryCode string    `json:"country_code"`
	Latitude    float64   `json:"lat"`
	Longitude   float64   `json:"lon"`
	Timestamp   time.Time `json:"ts"`
}

// ---------------------------------------------------------------------------
// Service errors
// ---------------------------------------------------------------------------

// TransactionError wraps domain-level errors with a machine-readable code.
type TransactionError struct {
	Code    string
	Message string
}

func (e *TransactionError) Error() string {
	return e.Code + ": " + e.Message
}

var (
	ErrTransactionNotFound = &TransactionError{Code: "TRANSACTION_NOT_FOUND", Message: "transaction not found"}
	ErrCustomerNotFound    = &TransactionError{Code: "CUSTOMER_NOT_FOUND", Message: "customer not found"}
	ErrDuplicateTransaction = &TransactionError{Code: "DUPLICATE_TRANSACTION", Message: "transaction already processed"}
	ErrMLServiceUnavailable = &TransactionError{Code: "ML_SERVICE_UNAVAILABLE", Message: "ML service is unavailable"}
	ErrInvalidTransaction   = &TransactionError{Code: "INVALID_TRANSACTION", Message: "transaction validation failed"}
)
