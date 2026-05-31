// Package service implements the core analytics business logic.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/fraud-detection/analytics-service/internal/domain"
)

// ---------------------------------------------------------------------------
// Port interfaces (dependency inversion)
// ---------------------------------------------------------------------------

// AlertStore defines read-only analytics queries against the alert database.
type AlertStore interface {
	GetFraudTrends(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.TrendPoint, error)
	GetRiskDistribution(ctx context.Context, from, to time.Time) ([]*domain.RiskBucket, error)
	GetTopRiskyCustomers(ctx context.Context, from, to time.Time, limit int) ([]*domain.RiskyCustomer, error)
	GetModelPerformance(ctx context.Context, modelVersion string, from, to time.Time) (*domain.ModelPerformance, error)
	GetAlertMetrics(ctx context.Context, from, to time.Time) (*domain.AlertMetrics, error)
	Ping(ctx context.Context) error
}

// TransactionStore defines read-only analytics queries against the transaction
// time-series database (MongoDB).
type TransactionStore interface {
	GetTransactionVolume(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.VolumePoint, error)
	GetGeographicDistribution(ctx context.Context, from, to time.Time) ([]*domain.GeoFraudPoint, error)
	GetCustomerAmounts(ctx context.Context, customerIDs []string, from, to time.Time) (map[string]float64, error)
	Ping(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// AnalyticsService orchestrates analytics queries across Postgres and MongoDB.
type AnalyticsService struct {
	alerts AlertStore
	txs    TransactionStore
	log    zerolog.Logger
}

// New constructs an AnalyticsService.
func New(alerts AlertStore, txs TransactionStore, log zerolog.Logger) *AnalyticsService {
	return &AnalyticsService{alerts: alerts, txs: txs, log: log}
}

// ---------------------------------------------------------------------------
// GetFraudTrends
// ---------------------------------------------------------------------------

// GetFraudTrends returns alert trend data for the given time range.
func (s *AnalyticsService) GetFraudTrends(ctx context.Context, from, to time.Time, gran domain.Granularity) (*domain.FraudTrendsResult, error) {
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to.Add(-7 * 24 * time.Hour)
	}
	if gran == "" {
		gran = domain.GranularityDay
	}

	points, err := s.alerts.GetFraudTrends(ctx, from, to, gran)
	if err != nil {
		return nil, fmt.Errorf("get fraud trends: %w", err)
	}

	// Enrich with MongoDB transaction volume to compute accurate fraud rates
	volPoints, err := s.txs.GetTransactionVolume(ctx, from, to, gran)
	if err != nil {
		s.log.Warn().Err(err).Msg("could not fetch transaction volume for fraud rate; using alert-only rate")
	} else {
		// Build a lookup by bucket date string
		volMap := make(map[string]*domain.VolumePoint, len(volPoints))
		for _, v := range volPoints {
			volMap[v.Date.Format("2006-01-02")] = v
		}
		for _, p := range points {
			key := p.Date.Format("2006-01-02")
			if v, ok := volMap[key]; ok {
				p.TotalTxCount = v.TxCount
				if v.TxCount > 0 {
					p.FraudRate = float64(p.FraudCount) / float64(v.TxCount)
				}
			}
		}
	}

	return &domain.FraudTrendsResult{
		Points:      points,
		Period:      fmt.Sprintf("%s to %s", from.Format("2006-01-02"), to.Format("2006-01-02")),
		Granularity: gran,
	}, nil
}

// ---------------------------------------------------------------------------
// GetRiskDistribution
// ---------------------------------------------------------------------------

// GetRiskDistribution returns alert counts by risk level for a named period.
func (s *AnalyticsService) GetRiskDistribution(ctx context.Context, period string) ([]*domain.RiskBucket, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}
	buckets, err := s.alerts.GetRiskDistribution(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("get risk distribution: %w", err)
	}
	return buckets, nil
}

// ---------------------------------------------------------------------------
// GetTopRiskyCustomers
// ---------------------------------------------------------------------------

// GetTopRiskyCustomers returns the highest-risk customers ranked by alert count.
func (s *AnalyticsService) GetTopRiskyCustomers(ctx context.Context, period string, limit int) ([]*domain.RiskyCustomer, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	customers, err := s.alerts.GetTopRiskyCustomers(ctx, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("get top risky customers: %w", err)
	}

	// Enrich with total transaction amounts from MongoDB
	if len(customers) > 0 {
		ids := make([]string, len(customers))
		for i, c := range customers {
			ids[i] = c.CustomerID
		}
		amountMap, amErr := s.txs.GetCustomerAmounts(ctx, ids, from, to)
		if amErr != nil {
			s.log.Warn().Err(amErr).Msg("could not fetch customer amounts from MongoDB")
		} else {
			for _, c := range customers {
				c.TotalAmount = amountMap[c.CustomerID]
			}
		}
	}

	return customers, nil
}

// ---------------------------------------------------------------------------
// GetModelPerformance
// ---------------------------------------------------------------------------

// GetModelPerformance computes prediction quality metrics for a model version.
func (s *AnalyticsService) GetModelPerformance(ctx context.Context, modelVersion, period string) (*domain.ModelPerformance, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}
	perf, err := s.alerts.GetModelPerformance(ctx, modelVersion, from, to)
	if err != nil {
		return nil, fmt.Errorf("get model performance: %w", err)
	}
	perf.Period = period
	return perf, nil
}

// ---------------------------------------------------------------------------
// GetTransactionVolume
// ---------------------------------------------------------------------------

// GetTransactionVolume returns transaction volume time-series from MongoDB.
func (s *AnalyticsService) GetTransactionVolume(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.VolumePoint, error) {
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to.Add(-7 * 24 * time.Hour)
	}
	if gran == "" {
		gran = domain.GranularityDay
	}
	points, err := s.txs.GetTransactionVolume(ctx, from, to, gran)
	if err != nil {
		return nil, fmt.Errorf("get transaction volume: %w", err)
	}
	return points, nil
}

// ---------------------------------------------------------------------------
// GetAlertMetrics
// ---------------------------------------------------------------------------

// GetAlertMetrics returns detailed alert lifecycle metrics for a named period.
func (s *AnalyticsService) GetAlertMetrics(ctx context.Context, period string) (*domain.AlertMetrics, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}
	metrics, err := s.alerts.GetAlertMetrics(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("get alert metrics: %w", err)
	}
	metrics.Period = period
	return metrics, nil
}

// ---------------------------------------------------------------------------
// GetGeographicDistribution
// ---------------------------------------------------------------------------

// GetGeographicDistribution returns per-country fraud breakdown from MongoDB.
func (s *AnalyticsService) GetGeographicDistribution(ctx context.Context, period string) ([]*domain.GeoFraudPoint, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}
	points, err := s.txs.GetGeographicDistribution(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("get geographic distribution: %w", err)
	}
	return points, nil
}

// ---------------------------------------------------------------------------
// GenerateReport
// ---------------------------------------------------------------------------

// GenerateReport builds a structured JSON report for the given type and period.
func (s *AnalyticsService) GenerateReport(ctx context.Context, reportType domain.ReportType, period string) (*domain.Report, error) {
	from, to, err := domain.PeriodRange(period)
	if err != nil {
		return nil, err
	}

	var content interface{}
	switch reportType {
	case domain.ReportTypeSummary:
		content, err = s.buildSummaryReport(ctx, period, from, to)
	case domain.ReportTypeCompliance:
		content, err = s.buildComplianceReport(ctx, period, from, to)
	case domain.ReportTypeSAR:
		content, err = s.buildSARReport(ctx, period, from, to)
	case domain.ReportTypeModelAudit:
		content, err = s.buildModelAuditReport(ctx, period, from, to)
	default:
		return nil, fmt.Errorf("unknown report type: %s", reportType)
	}
	if err != nil {
		return nil, fmt.Errorf("build report: %w", err)
	}

	jsonBytes, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	return &domain.Report{
		ReportID:    uuid.NewString(),
		ReportType:  reportType,
		Period:      period,
		GeneratedAt: time.Now().UTC(),
		ContentJSON: string(jsonBytes),
	}, nil
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

// HealthCheck returns true if both Postgres and MongoDB are reachable.
func (s *AnalyticsService) HealthCheck(ctx context.Context) (pgOK, mongoOK bool, pgErr, mongoErr error) {
	pgErr = s.alerts.Ping(ctx)
	pgOK = pgErr == nil
	mongoErr = s.txs.Ping(ctx)
	mongoOK = mongoErr == nil
	return
}

// ---------------------------------------------------------------------------
// Report builders
// ---------------------------------------------------------------------------

type summaryReport struct {
	Period         string                 `json:"period"`
	GeneratedAt    time.Time              `json:"generated_at"`
	AlertMetrics   *domain.AlertMetrics   `json:"alert_metrics"`
	RiskDistrib    []*domain.RiskBucket   `json:"risk_distribution"`
	TopCustomers   []*domain.RiskyCustomer `json:"top_risky_customers"`
	ModelPerf      *domain.ModelPerformance `json:"model_performance"`
}

func (s *AnalyticsService) buildSummaryReport(ctx context.Context, period string, from, to time.Time) (*summaryReport, error) {
	metrics, err := s.alerts.GetAlertMetrics(ctx, from, to)
	if err != nil {
		return nil, err
	}
	metrics.Period = period

	buckets, err := s.alerts.GetRiskDistribution(ctx, from, to)
	if err != nil {
		return nil, err
	}

	customers, err := s.alerts.GetTopRiskyCustomers(ctx, from, to, 10)
	if err != nil {
		return nil, err
	}

	perf, err := s.alerts.GetModelPerformance(ctx, "", from, to)
	if err != nil {
		return nil, err
	}
	perf.Period = period

	return &summaryReport{
		Period:       period,
		GeneratedAt:  time.Now().UTC(),
		AlertMetrics: metrics,
		RiskDistrib:  buckets,
		TopCustomers: customers,
		ModelPerf:    perf,
	}, nil
}

type complianceReport struct {
	Period          string                   `json:"period"`
	GeneratedAt     time.Time                `json:"generated_at"`
	AlertMetrics    *domain.AlertMetrics     `json:"alert_metrics"`
	RiskDistrib     []*domain.RiskBucket     `json:"risk_distribution"`
	GeoDistrib      []*domain.GeoFraudPoint  `json:"geographic_distribution"`
	TopCustomers    []*domain.RiskyCustomer  `json:"top_risky_customers"`
	ModelPerf       *domain.ModelPerformance `json:"model_performance"`
	ComplianceNotes string                   `json:"compliance_notes"`
}

func (s *AnalyticsService) buildComplianceReport(ctx context.Context, period string, from, to time.Time) (*complianceReport, error) {
	summary, err := s.buildSummaryReport(ctx, period, from, to)
	if err != nil {
		return nil, err
	}
	geo, err := s.txs.GetGeographicDistribution(ctx, from, to)
	if err != nil {
		s.log.Warn().Err(err).Msg("geographic distribution unavailable for compliance report")
	}
	return &complianceReport{
		Period:          period,
		GeneratedAt:     time.Now().UTC(),
		AlertMetrics:    summary.AlertMetrics,
		RiskDistrib:     summary.RiskDistrib,
		GeoDistrib:      geo,
		TopCustomers:    summary.TopCustomers,
		ModelPerf:       summary.ModelPerf,
		ComplianceNotes: fmt.Sprintf("Automated compliance report for period %s. Generated %s.", period, time.Now().UTC().Format(time.RFC3339)),
	}, nil
}

type sarReport struct {
	Period        string                  `json:"period"`
	GeneratedAt   time.Time               `json:"generated_at"`
	TotalSARItems int                     `json:"total_sar_items"`
	HighRiskCases []*domain.RiskyCustomer `json:"high_risk_cases"`
	Notes         string                  `json:"notes"`
}

func (s *AnalyticsService) buildSARReport(ctx context.Context, period string, from, to time.Time) (*sarReport, error) {
	customers, err := s.alerts.GetTopRiskyCustomers(ctx, from, to, 50)
	if err != nil {
		return nil, err
	}
	// SAR: only include customers with fraud_rate > 0.5 or > 3 alerts
	var sarItems []*domain.RiskyCustomer
	for _, c := range customers {
		if c.FraudRate > 0.5 || c.AlertCount >= 3 {
			sarItems = append(sarItems, c)
		}
	}
	return &sarReport{
		Period:        period,
		GeneratedAt:   time.Now().UTC(),
		TotalSARItems: len(sarItems),
		HighRiskCases: sarItems,
		Notes:         fmt.Sprintf("Suspicious Activity Report candidates for %s. Criteria: fraud_rate > 0.5 OR alert_count >= 3.", period),
	}, nil
}

type modelAuditReport struct {
	Period        string                   `json:"period"`
	GeneratedAt   time.Time                `json:"generated_at"`
	Performance   *domain.ModelPerformance `json:"performance"`
	RiskDistrib   []*domain.RiskBucket     `json:"risk_distribution"`
	Recommendations []string               `json:"recommendations"`
}

func (s *AnalyticsService) buildModelAuditReport(ctx context.Context, period string, from, to time.Time) (*modelAuditReport, error) {
	perf, err := s.alerts.GetModelPerformance(ctx, "", from, to)
	if err != nil {
		return nil, err
	}
	perf.Period = period

	buckets, err := s.alerts.GetRiskDistribution(ctx, from, to)
	if err != nil {
		return nil, err
	}

	var recs []string
	if perf.Precision < 0.90 {
		recs = append(recs, fmt.Sprintf("Precision %.2f%% is below 90%% target — consider retraining with recent data.", perf.Precision*100))
	}
	if perf.Recall < 0.85 {
		recs = append(recs, fmt.Sprintf("Recall %.2f%% is below 85%% target — review false-negative patterns.", perf.Recall*100))
	}
	if len(recs) == 0 {
		recs = append(recs, "All model metrics within acceptable thresholds.")
	}

	return &modelAuditReport{
		Period:          period,
		GeneratedAt:     time.Now().UTC(),
		Performance:     perf,
		RiskDistrib:     buckets,
		Recommendations: recs,
	}, nil
}
