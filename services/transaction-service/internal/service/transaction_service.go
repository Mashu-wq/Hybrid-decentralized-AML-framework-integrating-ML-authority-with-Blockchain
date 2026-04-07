// Package service implements the core business logic for the Transaction
// Monitoring Service. The TransactionService orchestrates the complete
// processing pipeline:
//
//  1. Feature extraction (temporal, velocity, geographic, merchant, KYC)
//  2. ML fraud prediction via gRPC (PredictFraud)
//  3. Velocity update in Redis (sorted sets + last_tx cache)
//  4. Enriched transaction persistence in MongoDB (time-series collection)
//  5. Alert publication to Kafka alerts.created (if fraud_probability > threshold)
//  6. Risk score caching in Redis (5-min TTL)
//
// Every step after feature extraction is non-blocking on its own error —
// prediction failures fall back to a heuristic, storage failures are logged
// but do not roll back the in-memory result.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Port interfaces (dependency inversion — no direct imports of impl packages)
// ---------------------------------------------------------------------------

// FeatureExtractor computes the feature vector for a raw transaction.
type FeatureExtractor interface {
	Extract(ctx context.Context, raw *domain.RawTransaction) (*domain.TransactionFeatures, error)
	PipelineVersion() string
}

// FraudPredictor calls the ML service and returns a fraud prediction.
type FraudPredictor interface {
	PredictFraud(ctx context.Context, f *domain.TransactionFeatures) (*domain.FraudPrediction, error)
	HealthCheck(ctx context.Context) error
}

// TransactionStore persists and retrieves enriched transactions.
type TransactionStore interface {
	Save(ctx context.Context, tx *domain.EnrichedTransaction) error
	GetByTxHash(ctx context.Context, txHash string) (*domain.EnrichedTransaction, error)
	GetCustomerHistory(ctx context.Context, customerID string, startTime, endTime time.Time, minFraudProb float64, pageSize int, pageToken string) ([]*domain.EnrichedTransaction, string, error)
	ComputeFraudRate30D(ctx context.Context, customerID string) (float64, int, error)
	Ping(ctx context.Context) error
}

// VelocityStore records velocity data and reads cached risk scores.
type VelocityStore interface {
	RecordTransaction(ctx context.Context, raw *domain.RawTransaction, amountUSD float64) error
	CacheRiskScore(ctx context.Context, score *domain.CachedRiskScore) error
	GetCachedRiskScore(ctx context.Context, customerID string) (*domain.CachedRiskScore, error)
	GetVelocityStats(ctx context.Context, customerID string, alert1HLimit, alert24HLimit int) (*domain.VelocityStats, error)
	Ping(ctx context.Context) error
}

// AlertPublisher publishes AlertEvent messages to the alerts.created Kafka topic.
type AlertPublisher interface {
	PublishAlert(ctx context.Context, alert *domain.AlertEvent) error
	Close() error
}

// ---------------------------------------------------------------------------
// TransactionService
// ---------------------------------------------------------------------------

// TransactionService is the central orchestrator for transaction monitoring.
type TransactionService struct {
	extractor      FeatureExtractor
	predictor      FraudPredictor
	txStore        TransactionStore
	velocityStore  VelocityStore
	alertPublisher AlertPublisher
	log            zerolog.Logger

	alertThreshold    float64 // publish alert if fraud_prob > this
	velocity1HLimit   int
	velocity24HLimit  int
}

// Config holds TransactionService configuration.
type Config struct {
	AlertThreshold    float64
	Velocity1HLimit   int
	Velocity24HLimit  int
}

// NewTransactionService constructs a fully wired TransactionService.
func NewTransactionService(
	extractor FeatureExtractor,
	predictor FraudPredictor,
	txStore TransactionStore,
	velocityStore VelocityStore,
	alertPublisher AlertPublisher,
	cfg Config,
	log zerolog.Logger,
) *TransactionService {
	return &TransactionService{
		extractor:      extractor,
		predictor:      predictor,
		txStore:        txStore,
		velocityStore:  velocityStore,
		alertPublisher: alertPublisher,
		log:            log.With().Str("component", "transaction_service").Logger(),
		alertThreshold:   cfg.AlertThreshold,
		velocity1HLimit:  cfg.Velocity1HLimit,
		velocity24HLimit: cfg.Velocity24HLimit,
	}
}

// ---------------------------------------------------------------------------
// Core pipeline
// ---------------------------------------------------------------------------

// ProcessTransaction executes the complete fraud detection pipeline for one transaction.
// It is called by both the Kafka consumer (async path) and the IngestTransaction
// gRPC handler with sync=true (synchronous path).
//
// Pipeline steps:
//  1. Validate input
//  2. Extract features (Redis lookups for velocity, last_tx, profile, country history)
//  3. Call ML service PredictFraud (with heuristic fallback on unavailability)
//  4. Update Redis: velocity sorted set, last_tx cache, risk score (5-min TTL)
//  5. Store enriched transaction in MongoDB
//  6. If fraud_probability > threshold → publish AlertEvent to Kafka
//
// Returns the fully enriched transaction record.
func (s *TransactionService) ProcessTransaction(ctx context.Context, raw *domain.RawTransaction) (*domain.EnrichedTransaction, error) {
	log := s.log.With().
		Str("tx_hash", raw.TxHash).
		Str("customer_id", raw.CustomerID).
		Logger()

	start := time.Now()

	// --- Step 1: Validate ---
	if err := raw.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidTransaction, err.Error())
	}

	// --- Step 2: Extract features ---
	f, err := s.extractor.Extract(ctx, raw)
	if err != nil {
		// Feature extraction is critical — fail fast (but Extract only fails on
		// programmer errors; Redis failures return safe defaults, not errors).
		return nil, fmt.Errorf("feature extraction failed for %s: %w", raw.TxHash, err)
	}

	// --- Step 3: ML prediction ---
	prediction, err := s.predictor.PredictFraud(ctx, f)
	if err != nil {
		// Should never happen — PredictFraud returns a fallback on ML unavailability.
		log.Error().Err(err).Msg("unexpected error from PredictFraud; using zero prediction")
		prediction = &domain.FraudPrediction{
			FraudProbability: 0,
			RiskLevel:        domain.RiskLevelLow,
			ModelVersion:     "error-fallback",
			PredictedAt:      time.Now().UTC(),
		}
	}

	processedAt := time.Now().UTC()

	// --- Step 4: Update Redis (non-fatal) ---
	if err := s.velocityStore.RecordTransaction(ctx, raw, f.AmountUSDEquiv); err != nil {
		log.Warn().Err(err).Msg("failed to update velocity Redis; continuing")
	}

	riskScore := fraudProbToScore(prediction.FraudProbability)
	cachedScore := &domain.CachedRiskScore{
		CustomerID:   raw.CustomerID,
		RiskScore:    riskScore,
		RiskLevel:    prediction.RiskLevel,
		ComputedAt:   processedAt,
	}
	if err := s.velocityStore.CacheRiskScore(ctx, cachedScore); err != nil {
		log.Warn().Err(err).Msg("failed to cache risk score; continuing")
	}

	// --- Build enriched transaction ---
	enriched := &domain.EnrichedTransaction{
		TxHash:           raw.TxHash,
		CustomerID:       raw.CustomerID,
		Raw:              raw,
		Features:         f,
		FraudProbability: prediction.FraudProbability,
		IsFraud:          prediction.IsFraud,
		RiskLevel:        prediction.RiskLevel,
		ModelVersion:     prediction.ModelVersion,
		PredictionID:     prediction.PredictionID,
		SHAPValues:       prediction.SHAPValues,
		ProcessedAt:      processedAt,
	}

	// --- Step 5: Publish alert (if above threshold) ---
	if prediction.FraudProbability > s.alertThreshold {
		alertEvent, err := s.buildAlertEvent(enriched, prediction)
		if err != nil {
			log.Error().Err(err).Msg("failed to build alert event; skipping alert")
		} else {
			if err := s.alertPublisher.PublishAlert(ctx, alertEvent); err != nil {
				log.Error().Err(err).Str("alert_id", alertEvent.AlertID).Msg("failed to publish alert to Kafka")
				// Non-fatal: continue — the enriched transaction is still stored.
			} else {
				enriched.AlertCreated = true
				enriched.AlertID = alertEvent.AlertID
				log.Info().
					Str("alert_id", alertEvent.AlertID).
					Float64("fraud_prob", prediction.FraudProbability).
					Str("risk_level", prediction.RiskLevel.String()).
					Msg("alert published to Kafka")
			}
		}
	}

	// --- Step 6: Persist to MongoDB (non-fatal) ---
	if err := s.txStore.Save(ctx, enriched); err != nil {
		log.Error().Err(err).Msg("failed to persist enriched transaction to MongoDB")
		// Return the enriched result anyway — the caller (gRPC sync) still needs it.
	}

	log.Info().
		Float64("fraud_prob", prediction.FraudProbability).
		Str("risk_level", prediction.RiskLevel.String()).
		Bool("alert_created", enriched.AlertCreated).
		Dur("pipeline_ms", time.Since(start)).
		Msg("transaction processing complete")

	return enriched, nil
}

// ---------------------------------------------------------------------------
// Query methods
// ---------------------------------------------------------------------------

// GetTransaction retrieves a stored enriched transaction by tx_hash.
func (s *TransactionService) GetTransaction(ctx context.Context, txHash string) (*domain.EnrichedTransaction, error) {
	if txHash == "" {
		return nil, fmt.Errorf("tx_hash is required")
	}
	return s.txStore.GetByTxHash(ctx, txHash)
}

// GetCustomerHistory returns a paginated list of enriched transactions for a customer.
func (s *TransactionService) GetCustomerHistory(
	ctx context.Context,
	customerID string,
	startTime, endTime time.Time,
	minFraudProb float64,
	pageSize int,
	pageToken string,
) ([]*domain.EnrichedTransaction, string, error) {
	if customerID == "" {
		return nil, "", fmt.Errorf("customer_id is required")
	}
	return s.txStore.GetCustomerHistory(ctx, customerID, startTime, endTime, minFraudProb, pageSize, pageToken)
}

// GetRiskScore returns the current cached risk score for a customer.
// Falls back to computing from MongoDB fraud rate if the cache is empty.
func (s *TransactionService) GetRiskScore(ctx context.Context, customerID string) (*domain.CachedRiskScore, error) {
	if customerID == "" {
		return nil, fmt.Errorf("customer_id is required")
	}

	// Try Redis cache first (5-min TTL)
	cached, err := s.velocityStore.GetCachedRiskScore(ctx, customerID)
	if err != nil {
		s.log.Warn().Err(err).Str("customer_id", customerID).Msg("cache miss — falling back to MongoDB")
	}
	if cached != nil {
		return cached, nil
	}

	// Fallback: compute from MongoDB 30-day fraud rate
	fraudRate, alertCount, err := s.txStore.ComputeFraudRate30D(ctx, customerID)
	if err != nil {
		return nil, fmt.Errorf("compute fraud rate for %s: %w", customerID, err)
	}

	score := &domain.CachedRiskScore{
		CustomerID:    customerID,
		RiskScore:     fraudRate * 100,
		RiskLevel:     domain.FraudProbToRiskLevel(fraudRate),
		FraudRate30D:  fraudRate,
		AlertCount30D: alertCount,
		ComputedAt:    time.Now().UTC(),
	}

	// Re-populate the cache
	if err := s.velocityStore.CacheRiskScore(ctx, score); err != nil {
		s.log.Warn().Err(err).Str("customer_id", customerID).Msg("failed to re-cache risk score")
	}

	return score, nil
}

// GetVelocityStats returns real-time velocity statistics for a customer.
func (s *TransactionService) GetVelocityStats(ctx context.Context, customerID string) (*domain.VelocityStats, error) {
	if customerID == "" {
		return nil, fmt.Errorf("customer_id is required")
	}
	return s.velocityStore.GetVelocityStats(ctx, customerID, s.velocity1HLimit, s.velocity24HLimit)
}

// HealthCheck verifies connectivity to all downstream dependencies.
func (s *TransactionService) HealthCheck(ctx context.Context) error {
	if err := s.txStore.Ping(ctx); err != nil {
		return fmt.Errorf("MongoDB unhealthy: %w", err)
	}
	if err := s.velocityStore.Ping(ctx); err != nil {
		return fmt.Errorf("Redis unhealthy: %w", err)
	}
	if err := s.predictor.HealthCheck(ctx); err != nil {
		// ML service health check is non-fatal (we have a heuristic fallback)
		s.log.Warn().Err(err).Msg("ML service health check failed (non-fatal)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildAlertEvent constructs an AlertEvent from an enriched transaction.
func (s *TransactionService) buildAlertEvent(enriched *domain.EnrichedTransaction, prediction *domain.FraudPrediction) (*domain.AlertEvent, error) {
	alertID := uuid.New().String()

	// Serialise SHAP values for storage in the Alert Service's PostgreSQL JSONB column.
	shapJSON := "[]"
	if len(prediction.SHAPValues) > 0 {
		b, err := json.Marshal(prediction.SHAPValues)
		if err != nil {
			return nil, fmt.Errorf("marshal SHAP values: %w", err)
		}
		shapJSON = string(b)
	}

	// Serialise feature snapshot for audit reproducibility.
	featuresJSON := "{}"
	if enriched.Features != nil {
		b, err := json.Marshal(enriched.Features)
		if err != nil {
			s.log.Warn().Err(err).Msg("failed to serialise features snapshot; using empty object")
		} else {
			featuresJSON = string(b)
		}
	}

	return &domain.AlertEvent{
		AlertID:              alertID,
		CustomerID:           enriched.CustomerID,
		TxHash:               enriched.TxHash,
		FraudProbability:     prediction.FraudProbability,
		RiskScore:            fraudProbToScore(prediction.FraudProbability),
		RiskLevel:            prediction.RiskLevel.String(),
		ModelVersion:         prediction.ModelVersion,
		SHAPExplanationJSON:  shapJSON,
		FeaturesSnapshotJSON: featuresJSON,
		CreatedAt:            enriched.ProcessedAt,
	}, nil
}

// fraudProbToScore converts a [0,1] fraud probability to a [0,100] risk score.
func fraudProbToScore(prob float64) float64 {
	if prob < 0 {
		return 0
	}
	if prob > 1 {
		return 100
	}
	return prob * 100
}

// TODO: Add compile-time interface assertion for FeatureExtractor once
// the features package is confirmed stable:
// var _ FeatureExtractor = (*features.Extractor)(nil)
