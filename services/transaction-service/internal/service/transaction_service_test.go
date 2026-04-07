package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/fraud-detection/transaction-service/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles (inline mocks — no gomock to keep deps minimal)
// ---------------------------------------------------------------------------

type mockExtractor struct {
	features *domain.TransactionFeatures
	err      error
}

func (m *mockExtractor) Extract(_ context.Context, raw *domain.RawTransaction) (*domain.TransactionFeatures, error) {
	if m.err != nil {
		return nil, m.err
	}
	f := m.features
	if f == nil {
		f = &domain.TransactionFeatures{
			TxHash:          raw.TxHash,
			CustomerID:      raw.CustomerID,
			Amount:          raw.Amount,
			CurrencyCode:    raw.CurrencyCode,
			AmountUSDEquiv:  raw.Amount,
			CountryCode:     raw.CountryCode,
			GeographicRiskScore: 20,
			MerchantRiskScore:   15,
			HopsToKnownFraudster: -1,
		}
	}
	return f, nil
}

func (m *mockExtractor) PipelineVersion() string { return "test-v1" }

// -----

type mockPredictor struct {
	prediction *domain.FraudPrediction
	err        error
}

func (m *mockPredictor) PredictFraud(_ context.Context, _ *domain.TransactionFeatures) (*domain.FraudPrediction, error) {
	if m.err != nil {
		return nil, m.err
	}
	p := m.prediction
	if p == nil {
		p = &domain.FraudPrediction{
			FraudProbability: 0.3,
			IsFraud:          false,
			RiskLevel:        domain.RiskLevelLow,
			ModelVersion:     "test-ensemble-v1",
			PredictionID:     "pred-001",
			PredictedAt:      time.Now().UTC(),
		}
	}
	return p, nil
}

func (m *mockPredictor) HealthCheck(_ context.Context) error { return nil }

// -----

type mockTxStore struct {
	saved    []*domain.EnrichedTransaction
	err      error
	findErr  error
	history  []*domain.EnrichedTransaction
	rate     float64
	alerts   int
}

func (m *mockTxStore) Save(_ context.Context, tx *domain.EnrichedTransaction) error {
	if m.err != nil {
		return m.err
	}
	m.saved = append(m.saved, tx)
	return nil
}

func (m *mockTxStore) GetByTxHash(_ context.Context, txHash string) (*domain.EnrichedTransaction, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	for _, tx := range m.saved {
		if tx.TxHash == txHash {
			return tx, nil
		}
	}
	return nil, domain.ErrTransactionNotFound
}

func (m *mockTxStore) GetCustomerHistory(_ context.Context, _ string, _, _ time.Time, _ float64, _ int, _ string) ([]*domain.EnrichedTransaction, string, error) {
	return m.history, "", nil
}

func (m *mockTxStore) ComputeFraudRate30D(_ context.Context, _ string) (float64, int, error) {
	return m.rate, m.alerts, nil
}

func (m *mockTxStore) Ping(_ context.Context) error { return nil }

// -----

type mockVelocityStore struct {
	err        error
	riskScore  *domain.CachedRiskScore
	stats      *domain.VelocityStats
}

func (m *mockVelocityStore) RecordTransaction(_ context.Context, _ *domain.RawTransaction, _ float64) error {
	return m.err
}

func (m *mockVelocityStore) CacheRiskScore(_ context.Context, _ *domain.CachedRiskScore) error {
	return m.err
}

func (m *mockVelocityStore) GetCachedRiskScore(_ context.Context, _ string) (*domain.CachedRiskScore, error) {
	return m.riskScore, m.err
}

func (m *mockVelocityStore) GetVelocityStats(_ context.Context, _ string, _, _ int) (*domain.VelocityStats, error) {
	if m.stats != nil {
		return m.stats, nil
	}
	return &domain.VelocityStats{}, nil
}

func (m *mockVelocityStore) Ping(_ context.Context) error { return nil }

// -----

type mockAlertPublisher struct {
	published []*domain.AlertEvent
	err       error
}

func (m *mockAlertPublisher) PublishAlert(_ context.Context, alert *domain.AlertEvent) error {
	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, alert)
	return nil
}

func (m *mockAlertPublisher) Close() error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildSvc(
	extractor service.FeatureExtractor,
	predictor service.FraudPredictor,
	txStore service.TransactionStore,
	velStore service.VelocityStore,
	alertPub service.AlertPublisher,
) *service.TransactionService {
	cfg := service.Config{
		AlertThreshold:   0.7,
		Velocity1HLimit:  20,
		Velocity24HLimit: 100,
	}
	return service.NewTransactionService(extractor, predictor, txStore, velStore, alertPub, cfg, zerolog.Nop())
}

func sampleRaw() *domain.RawTransaction {
	return &domain.RawTransaction{
		TxHash:        "tx-abc-123",
		CustomerID:    "cust-001",
		Amount:        500.00,
		CurrencyCode:  "USD",
		MerchantID:    "merch-01",
		MerchantName:  "Amazon",
		MerchantCategory: "e-commerce",
		CountryCode:   "US",
		Channel:       "CARD_NOT_PRESENT",
		TransactionAt: time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------------
// ProcessTransaction tests
// ---------------------------------------------------------------------------

func TestProcessTransaction_HappyPath_NoAlert(t *testing.T) {
	txStore := &mockTxStore{}
	alertPub := &mockAlertPublisher{}
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, txStore, &mockVelocityStore{}, alertPub)

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)

	assert.Equal(t, "tx-abc-123", result.TxHash)
	assert.Equal(t, "cust-001", result.CustomerID)
	assert.Equal(t, 0.3, result.FraudProbability)
	assert.Equal(t, domain.RiskLevelLow, result.RiskLevel)
	assert.False(t, result.AlertCreated)
	assert.Empty(t, result.AlertID)

	require.Len(t, txStore.saved, 1)
	assert.Equal(t, "tx-abc-123", txStore.saved[0].TxHash)
	assert.Len(t, alertPub.published, 0)
}

func TestProcessTransaction_HighFraudProb_CreatesAlert(t *testing.T) {
	txStore := &mockTxStore{}
	alertPub := &mockAlertPublisher{}
	predictor := &mockPredictor{
		prediction: &domain.FraudPrediction{
			FraudProbability: 0.92,
			IsFraud:          true,
			RiskLevel:        domain.RiskLevelCritical,
			ModelVersion:     "ensemble-v2",
			PredictionID:     "pred-999",
			PredictedAt:      time.Now().UTC(),
			SHAPValues: []domain.SHAPContribution{
				{FeatureName: "velocity_1h", FeatureValue: 5000, SHAPValue: 0.35, AbsImportance: 0.35},
			},
		},
	}
	svc := buildSvc(&mockExtractor{}, predictor, txStore, &mockVelocityStore{}, alertPub)

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)

	assert.True(t, result.AlertCreated)
	assert.NotEmpty(t, result.AlertID)
	assert.Equal(t, domain.RiskLevelCritical, result.RiskLevel)

	require.Len(t, alertPub.published, 1)
	alert := alertPub.published[0]
	assert.Equal(t, "cust-001", alert.CustomerID)
	assert.Equal(t, "tx-abc-123", alert.TxHash)
	assert.Equal(t, 0.92, alert.FraudProbability)
	assert.Equal(t, "CRITICAL", alert.RiskLevel)
	assert.NotEmpty(t, alert.SHAPExplanationJSON)
}

func TestProcessTransaction_ExactlyAtThreshold_NoAlert(t *testing.T) {
	// Threshold is 0.7 — strictly greater than triggers alert.
	predictor := &mockPredictor{
		prediction: &domain.FraudPrediction{
			FraudProbability: 0.7,
			IsFraud:          false,
			RiskLevel:        domain.RiskLevelHigh,
			ModelVersion:     "test-v1",
			PredictedAt:      time.Now().UTC(),
		},
	}
	alertPub := &mockAlertPublisher{}
	svc := buildSvc(&mockExtractor{}, predictor, &mockTxStore{}, &mockVelocityStore{}, alertPub)

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)
	assert.False(t, result.AlertCreated, "probability == threshold should NOT create alert")
	assert.Len(t, alertPub.published, 0)
}

func TestProcessTransaction_InvalidTransaction_ReturnsError(t *testing.T) {
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, &mockVelocityStore{}, &mockAlertPublisher{})

	badRaw := &domain.RawTransaction{
		// Missing TxHash, CustomerID, Amount
		TransactionAt: time.Now(),
	}
	_, err := svc.ProcessTransaction(context.Background(), badRaw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_hash is required")
}

func TestProcessTransaction_FeatureExtractionError_ReturnsError(t *testing.T) {
	extractor := &mockExtractor{err: errors.New("redis: connection refused")}
	svc := buildSvc(extractor, &mockPredictor{}, &mockTxStore{}, &mockVelocityStore{}, &mockAlertPublisher{})

	_, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "feature extraction failed")
}

func TestProcessTransaction_MongoSaveError_StillReturnsResult(t *testing.T) {
	// MongoDB failure is non-fatal — the enriched result is still returned.
	txStore := &mockTxStore{err: errors.New("mongo: timeout")}
	alertPub := &mockAlertPublisher{}
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, txStore, &mockVelocityStore{}, alertPub)

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)
	assert.Equal(t, "tx-abc-123", result.TxHash)
}

func TestProcessTransaction_AlertPublishError_StillReturnsResult(t *testing.T) {
	predictor := &mockPredictor{
		prediction: &domain.FraudPrediction{
			FraudProbability: 0.95,
			IsFraud:          true,
			RiskLevel:        domain.RiskLevelCritical,
			ModelVersion:     "v1",
			PredictedAt:      time.Now().UTC(),
		},
	}
	alertPub := &mockAlertPublisher{err: errors.New("kafka: broker unavailable")}
	svc := buildSvc(&mockExtractor{}, predictor, &mockTxStore{}, &mockVelocityStore{}, alertPub)

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)
	// Alert creation is attempted but fails — AlertCreated stays false
	assert.False(t, result.AlertCreated)
}

func TestProcessTransaction_MLPredictorError_UsesZeroPrediction(t *testing.T) {
	// The predictor mock returns an error — service should use zero prediction.
	predictor := &mockPredictor{err: errors.New("unexpected")}
	txStore := &mockTxStore{}
	svc := buildSvc(&mockExtractor{}, predictor, txStore, &mockVelocityStore{}, &mockAlertPublisher{})

	result, err := svc.ProcessTransaction(context.Background(), sampleRaw())
	require.NoError(t, err)
	// Zero prediction → no alert
	assert.False(t, result.AlertCreated)
	assert.Equal(t, domain.RiskLevelLow, result.RiskLevel)
}

// ---------------------------------------------------------------------------
// GetRiskScore tests
// ---------------------------------------------------------------------------

func TestGetRiskScore_CacheHit(t *testing.T) {
	cached := &domain.CachedRiskScore{
		CustomerID:   "cust-001",
		RiskScore:    85,
		RiskLevel:    domain.RiskLevelCritical,
		ComputedAt:   time.Now().UTC(),
	}
	velStore := &mockVelocityStore{riskScore: cached}
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, velStore, &mockAlertPublisher{})

	result, err := svc.GetRiskScore(context.Background(), "cust-001")
	require.NoError(t, err)
	assert.Equal(t, float64(85), result.RiskScore)
	assert.Equal(t, domain.RiskLevelCritical, result.RiskLevel)
}

func TestGetRiskScore_CacheMiss_FallsBackToMongo(t *testing.T) {
	velStore := &mockVelocityStore{riskScore: nil}
	txStore := &mockTxStore{rate: 0.25, alerts: 3}
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, txStore, velStore, &mockAlertPublisher{})

	result, err := svc.GetRiskScore(context.Background(), "cust-001")
	require.NoError(t, err)
	assert.Equal(t, 25.0, result.RiskScore) // 0.25 * 100
	assert.Equal(t, 3, result.AlertCount30D)
}

func TestGetRiskScore_EmptyCustomerID_Error(t *testing.T) {
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, &mockVelocityStore{}, &mockAlertPublisher{})
	_, err := svc.GetRiskScore(context.Background(), "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// FraudProbToRiskLevel tests
// ---------------------------------------------------------------------------

func TestFraudProbToRiskLevel(t *testing.T) {
	tests := []struct {
		prob     float64
		expected domain.RiskLevel
	}{
		{0.0, domain.RiskLevelLow},
		{0.4, domain.RiskLevelLow},
		{0.5, domain.RiskLevelMedium},
		{0.69, domain.RiskLevelMedium},
		{0.70, domain.RiskLevelHigh},
		{0.84, domain.RiskLevelHigh},
		{0.85, domain.RiskLevelCritical},
		{1.00, domain.RiskLevelCritical},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.expected, domain.FraudProbToRiskLevel(tt.prob))
		})
	}
}

// ---------------------------------------------------------------------------
// GetVelocityStats tests
// ---------------------------------------------------------------------------

func TestGetVelocityStats_EmptyCustomer(t *testing.T) {
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, &mockVelocityStore{}, &mockAlertPublisher{})
	_, err := svc.GetVelocityStats(context.Background(), "")
	require.Error(t, err)
}

func TestGetVelocityStats_VelocityAlertTriggered(t *testing.T) {
	velStore := &mockVelocityStore{
		stats: &domain.VelocityStats{
			CustomerID:      "cust-002",
			TxCount1H:       25, // > 20 limit
			TxCount24H:      50,
			VelocityAlert1H: true,
		},
	}
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, velStore, &mockAlertPublisher{})

	stats, err := svc.GetVelocityStats(context.Background(), "cust-002")
	require.NoError(t, err)
	assert.True(t, stats.VelocityAlert1H)
	assert.Equal(t, 25, stats.TxCount1H)
}

// ---------------------------------------------------------------------------
// HealthCheck tests
// ---------------------------------------------------------------------------

func TestHealthCheck_AllHealthy(t *testing.T) {
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &mockTxStore{}, &mockVelocityStore{}, &mockAlertPublisher{})
	assert.NoError(t, svc.HealthCheck(context.Background()))
}

func TestHealthCheck_MongoUnhealthy(t *testing.T) {
	txStore := &mockTxStore{}
	// Override Ping to fail
	svc := buildSvc(&mockExtractor{}, &mockPredictor{}, &failingPingStore{}, &mockVelocityStore{}, &mockAlertPublisher{})
	err := svc.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MongoDB unhealthy")
}

// failingPingStore is a TransactionStore whose Ping always fails.
type failingPingStore struct{ mockTxStore }

func (f *failingPingStore) Ping(_ context.Context) error {
	return errors.New("connection refused")
}
