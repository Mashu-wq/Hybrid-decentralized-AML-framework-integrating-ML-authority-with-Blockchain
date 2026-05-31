package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/rs/zerolog"

	"github.com/fraud-detection/analytics-service/internal/domain"
	"github.com/fraud-detection/analytics-service/internal/service"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockAlertStore struct{ mock.Mock }

func (m *mockAlertStore) GetFraudTrends(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.TrendPoint, error) {
	args := m.Called(ctx, from, to, gran)
	if v := args.Get(0); v != nil {
		return v.([]*domain.TrendPoint), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockAlertStore) GetRiskDistribution(ctx context.Context, from, to time.Time) ([]*domain.RiskBucket, error) {
	args := m.Called(ctx, from, to)
	if v := args.Get(0); v != nil {
		return v.([]*domain.RiskBucket), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockAlertStore) GetTopRiskyCustomers(ctx context.Context, from, to time.Time, limit int) ([]*domain.RiskyCustomer, error) {
	args := m.Called(ctx, from, to, limit)
	if v := args.Get(0); v != nil {
		return v.([]*domain.RiskyCustomer), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockAlertStore) GetModelPerformance(ctx context.Context, modelVersion string, from, to time.Time) (*domain.ModelPerformance, error) {
	args := m.Called(ctx, modelVersion, from, to)
	if v := args.Get(0); v != nil {
		return v.(*domain.ModelPerformance), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockAlertStore) GetAlertMetrics(ctx context.Context, from, to time.Time) (*domain.AlertMetrics, error) {
	args := m.Called(ctx, from, to)
	if v := args.Get(0); v != nil {
		return v.(*domain.AlertMetrics), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockAlertStore) Ping(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

type mockTxStore struct{ mock.Mock }

func (m *mockTxStore) GetTransactionVolume(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.VolumePoint, error) {
	args := m.Called(ctx, from, to, gran)
	if v := args.Get(0); v != nil {
		return v.([]*domain.VolumePoint), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockTxStore) GetGeographicDistribution(ctx context.Context, from, to time.Time) ([]*domain.GeoFraudPoint, error) {
	args := m.Called(ctx, from, to)
	if v := args.Get(0); v != nil {
		return v.([]*domain.GeoFraudPoint), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockTxStore) GetCustomerAmounts(ctx context.Context, customerIDs []string, from, to time.Time) (map[string]float64, error) {
	args := m.Called(ctx, customerIDs, from, to)
	if v := args.Get(0); v != nil {
		return v.(map[string]float64), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockTxStore) Ping(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildSvc(t *testing.T) (*service.AnalyticsService, *mockAlertStore, *mockTxStore) {
	t.Helper()
	alerts := &mockAlertStore{}
	txs := &mockTxStore{}
	log := zerolog.Nop()
	svc := service.New(alerts, txs, log)
	return svc, alerts, txs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGetFraudTrends_Success(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	now := time.Now().UTC()
	from := now.Add(-7 * 24 * time.Hour)
	to := now

	trendPts := []*domain.TrendPoint{
		{Date: from, AlertCount: 5, FraudCount: 3, AvgFraudProb: 0.82},
	}
	volPts := []*domain.VolumePoint{
		{Date: from, TxCount: 100, TotalAmount: 50000, FraudCount: 3},
	}

	alerts.On("GetFraudTrends", ctx, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), domain.GranularityDay).Return(trendPts, nil)
	txs.On("GetTransactionVolume", ctx, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), domain.GranularityDay).Return(volPts, nil)

	result, err := svc.GetFraudTrends(ctx, from, to, domain.GranularityDay)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Points, 1)
	assert.Equal(t, domain.GranularityDay, result.Granularity)
	alerts.AssertExpectations(t)
	txs.AssertExpectations(t)
}

func TestGetFraudTrends_DefaultsGranularity(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	alerts.On("GetFraudTrends", ctx, mock.Anything, mock.Anything, domain.GranularityDay).Return([]*domain.TrendPoint{}, nil)
	txs.On("GetTransactionVolume", ctx, mock.Anything, mock.Anything, domain.GranularityDay).Return([]*domain.VolumePoint{}, nil)

	// pass zero granularity — should default to day
	_, err := svc.GetFraudTrends(ctx, time.Time{}, time.Time{}, "")

	require.NoError(t, err)
	alerts.AssertExpectations(t)
}

func TestGetRiskDistribution_Success(t *testing.T) {
	ctx := context.Background()
	svc, alerts, _ := buildSvc(t)

	buckets := []*domain.RiskBucket{
		{RiskLevel: "HIGH", Count: 20, Percentage: 40.0, AvgFraudProb: 0.78},
		{RiskLevel: "CRITICAL", Count: 10, Percentage: 20.0, AvgFraudProb: 0.91},
	}
	alerts.On("GetRiskDistribution", ctx, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(buckets, nil)

	result, err := svc.GetRiskDistribution(ctx, "7d")

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "HIGH", result[0].RiskLevel)
	alerts.AssertExpectations(t)
}

func TestGetRiskDistribution_InvalidPeriod(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := buildSvc(t)

	_, err := svc.GetRiskDistribution(ctx, "banana")

	require.ErrorIs(t, err, domain.ErrInvalidPeriod)
}

func TestGetTopRiskyCustomers_EnrichesAmounts(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	customers := []*domain.RiskyCustomer{
		{CustomerID: "cust-1", AlertCount: 5, FraudRate: 0.8, AvgRiskScore: 85, LastAlertAt: time.Now()},
		{CustomerID: "cust-2", AlertCount: 3, FraudRate: 0.6, AvgRiskScore: 65, LastAlertAt: time.Now()},
	}
	amounts := map[string]float64{"cust-1": 12500.50, "cust-2": 8200.00}

	alerts.On("GetTopRiskyCustomers", ctx, mock.Anything, mock.Anything, 10).Return(customers, nil)
	txs.On("GetCustomerAmounts", ctx, []string{"cust-1", "cust-2"}, mock.Anything, mock.Anything).Return(amounts, nil)

	result, err := svc.GetTopRiskyCustomers(ctx, "30d", 10)

	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, 12500.50, result[0].TotalAmount)
	assert.Equal(t, 8200.00, result[1].TotalAmount)
}

func TestGetModelPerformance_ComputesMetrics(t *testing.T) {
	ctx := context.Background()
	svc, alerts, _ := buildSvc(t)

	perf := &domain.ModelPerformance{
		ModelVersion:     "v1.2",
		TotalPredictions: 100,
		TruePositives:    80,
		FalsePositives:   10,
		Precision:        0.888,
		Recall:           0.80,
		F1Score:          0.842,
		AUCROC:           0.95,
	}
	alerts.On("GetModelPerformance", ctx, "v1.2", mock.Anything, mock.Anything).Return(perf, nil)

	result, err := svc.GetModelPerformance(ctx, "v1.2", "30d")

	require.NoError(t, err)
	assert.Equal(t, "v1.2", result.ModelVersion)
	assert.Equal(t, "30d", result.Period)
	assert.Equal(t, int64(80), result.TruePositives)
}

func TestGetTransactionVolume_Success(t *testing.T) {
	ctx := context.Background()
	svc, _, txs := buildSvc(t)

	pts := []*domain.VolumePoint{
		{Date: time.Now().Add(-24 * time.Hour), TxCount: 200, TotalAmount: 100000, FraudCount: 5},
	}
	txs.On("GetTransactionVolume", ctx, mock.Anything, mock.Anything, domain.GranularityHour).Return(pts, nil)

	result, err := svc.GetTransactionVolume(ctx, time.Time{}, time.Time{}, domain.GranularityHour)

	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, 200, result[0].TxCount)
}

func TestGetAlertMetrics_Success(t *testing.T) {
	ctx := context.Background()
	svc, alerts, _ := buildSvc(t)

	metrics := &domain.AlertMetrics{
		TotalAlerts:       50,
		OpenAlerts:        10,
		ResolvedAlerts:    30,
		FalsePositives:    5,
		EscalatedAlerts:   5,
		AvgResolutionMin:  45.3,
		EscalationRate:    0.10,
		FalsePositiveRate: 0.143,
		ByPriority:        map[string]int{"LOW": 5, "MEDIUM": 15, "HIGH": 20, "CRITICAL": 10},
	}
	alerts.On("GetAlertMetrics", ctx, mock.Anything, mock.Anything).Return(metrics, nil)

	result, err := svc.GetAlertMetrics(ctx, "7d")

	require.NoError(t, err)
	assert.Equal(t, "7d", result.Period)
	assert.Equal(t, 50, result.TotalAlerts)
	assert.Equal(t, 4, len(result.ByPriority))
}

func TestGetGeographicDistribution_Success(t *testing.T) {
	ctx := context.Background()
	svc, _, txs := buildSvc(t)

	pts := []*domain.GeoFraudPoint{
		{CountryCode: "US", AlertCount: 30, TxCount: 500, FraudRate: 0.06, TotalAmount: 250000},
		{CountryCode: "CN", AlertCount: 20, TxCount: 300, FraudRate: 0.067, TotalAmount: 180000},
	}
	txs.On("GetGeographicDistribution", ctx, mock.Anything, mock.Anything).Return(pts, nil)

	result, err := svc.GetGeographicDistribution(ctx, "30d")

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "US", result[0].CountryCode)
}

func TestGenerateReport_Summary(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	metrics := &domain.AlertMetrics{TotalAlerts: 100, ByPriority: map[string]int{}}
	buckets := []*domain.RiskBucket{{RiskLevel: "HIGH", Count: 30}}
	customers := []*domain.RiskyCustomer{{CustomerID: "c1", AlertCount: 5}}
	perf := &domain.ModelPerformance{ModelVersion: "v1.0", Precision: 0.93, Recall: 0.88}

	alerts.On("GetAlertMetrics", ctx, mock.Anything, mock.Anything).Return(metrics, nil)
	alerts.On("GetRiskDistribution", ctx, mock.Anything, mock.Anything).Return(buckets, nil)
	alerts.On("GetTopRiskyCustomers", ctx, mock.Anything, mock.Anything, 10).Return(customers, nil)
	alerts.On("GetModelPerformance", ctx, "", mock.Anything, mock.Anything).Return(perf, nil)
	// summary builder doesn't call txs directly
	_ = txs

	report, err := svc.GenerateReport(ctx, domain.ReportTypeSummary, "7d")

	require.NoError(t, err)
	assert.Equal(t, domain.ReportTypeSummary, report.ReportType)
	assert.Equal(t, "7d", report.Period)
	assert.NotEmpty(t, report.ReportID)
	assert.NotEmpty(t, report.ContentJSON)
	assert.Contains(t, report.ContentJSON, "alert_metrics")
}

func TestGenerateReport_SAR(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	customers := []*domain.RiskyCustomer{
		{CustomerID: "sar-1", AlertCount: 5, FraudRate: 0.8},
		{CustomerID: "low-1", AlertCount: 1, FraudRate: 0.2},
	}
	alerts.On("GetTopRiskyCustomers", ctx, mock.Anything, mock.Anything, 50).Return(customers, nil)
	_ = txs

	report, err := svc.GenerateReport(ctx, domain.ReportTypeSAR, "30d")

	require.NoError(t, err)
	assert.Contains(t, report.ContentJSON, "sar-1")
	// low-risk customer should be excluded
	assert.NotContains(t, report.ContentJSON, "low-1")
}

func TestGenerateReport_InvalidType(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := buildSvc(t)

	_, err := svc.GenerateReport(ctx, domain.ReportType("INVALID"), "7d")
	require.Error(t, err)
}

func TestHealthCheck_AllHealthy(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	alerts.On("Ping", ctx).Return(nil)
	txs.On("Ping", ctx).Return(nil)

	pgOK, mongoOK, pgErr, mongoErr := svc.HealthCheck(ctx)

	assert.True(t, pgOK)
	assert.True(t, mongoOK)
	assert.NoError(t, pgErr)
	assert.NoError(t, mongoErr)
}

func TestHealthCheck_PostgresDown(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	alerts.On("Ping", ctx).Return(assert.AnError)
	txs.On("Ping", ctx).Return(nil)

	pgOK, mongoOK, pgErr, _ := svc.HealthCheck(ctx)

	assert.False(t, pgOK)
	assert.True(t, mongoOK)
	assert.Error(t, pgErr)
}

func TestHealthCheck_MongoDown(t *testing.T) {
	ctx := context.Background()
	svc, alerts, txs := buildSvc(t)

	alerts.On("Ping", ctx).Return(nil)
	txs.On("Ping", ctx).Return(assert.AnError)

	pgOK, mongoOK, _, mongoErr := svc.HealthCheck(ctx)

	assert.True(t, pgOK)
	assert.False(t, mongoOK)
	assert.Error(t, mongoErr)
}
