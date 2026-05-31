// Package postgres implements read-only analytics queries against PostgreSQL.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fraud-detection/analytics-service/internal/domain"
)

// AnalyticsRepository runs read-only analytics queries against the fraud_alerts
// and investigation_cases PostgreSQL tables.
type AnalyticsRepository struct {
	db *pgxpool.Pool
}

// New returns an AnalyticsRepository backed by the given connection pool.
func New(db *pgxpool.Pool) *AnalyticsRepository {
	return &AnalyticsRepository{db: db}
}

// Connect opens and validates a pgxpool connection.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// ---------------------------------------------------------------------------
// GetFraudTrends — time-series of alert counts grouped by date bucket
// ---------------------------------------------------------------------------

// GetFraudTrends returns alert trend data grouped by the given granularity.
func (r *AnalyticsRepository) GetFraudTrends(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.TrendPoint, error) {
	trunc, err := gran.PGTrunc()
	if err != nil {
		return nil, err
	}

	// priority >= 3 → HIGH or CRITICAL (confirmed suspicious)
	q := fmt.Sprintf(`
SELECT
    date_trunc('%s', created_at)                          AS bucket,
    COUNT(*)                                               AS alert_count,
    COUNT(*) FILTER (WHERE priority >= 3)                  AS fraud_count,
    COALESCE(AVG(fraud_probability), 0)                    AS avg_prob
FROM fraud_alerts
WHERE created_at BETWEEN $1 AND $2
GROUP BY 1
ORDER BY 1`, trunc)

	rows, err := r.db.Query(ctx, q, from, to)
	if err != nil {
		return nil, fmt.Errorf("fraud trends query: %w", err)
	}
	defer rows.Close()

	var points []*domain.TrendPoint
	for rows.Next() {
		p := &domain.TrendPoint{}
		var alertCount, fraudCount int
		var avgProb float64
		if err := rows.Scan(&p.Date, &alertCount, &fraudCount, &avgProb); err != nil {
			return nil, fmt.Errorf("scan trend row: %w", err)
		}
		p.AlertCount = alertCount
		p.FraudCount = fraudCount
		p.AvgFraudProb = avgProb
		// TotalTxCount and FraudRate are filled by the service layer from MongoDB
		points = append(points, p)
	}
	return points, rows.Err()
}

// ---------------------------------------------------------------------------
// GetRiskDistribution — alert counts by priority bucket
// ---------------------------------------------------------------------------

// GetRiskDistribution returns alert counts grouped by priority label.
func (r *AnalyticsRepository) GetRiskDistribution(ctx context.Context, from, to time.Time) ([]*domain.RiskBucket, error) {
	const q = `
SELECT
    CASE priority
        WHEN 1 THEN 'LOW'
        WHEN 2 THEN 'MEDIUM'
        WHEN 3 THEN 'HIGH'
        WHEN 4 THEN 'CRITICAL'
        ELSE 'UNKNOWN'
    END                             AS risk_level,
    COUNT(*)                        AS cnt,
    COALESCE(AVG(fraud_probability), 0) AS avg_prob
FROM fraud_alerts
WHERE created_at BETWEEN $1 AND $2
GROUP BY priority
ORDER BY priority`

	rows, err := r.db.Query(ctx, q, from, to)
	if err != nil {
		return nil, fmt.Errorf("risk distribution query: %w", err)
	}
	defer rows.Close()

	var buckets []*domain.RiskBucket
	var total int
	for rows.Next() {
		b := &domain.RiskBucket{}
		if err := rows.Scan(&b.RiskLevel, &b.Count, &b.AvgFraudProb); err != nil {
			return nil, fmt.Errorf("scan risk bucket: %w", err)
		}
		total += b.Count
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// compute percentage
	for _, b := range buckets {
		if total > 0 {
			b.Percentage = float64(b.Count) / float64(total) * 100
		}
	}
	return buckets, nil
}

// ---------------------------------------------------------------------------
// GetTopRiskyCustomers — customers ranked by alert count
// ---------------------------------------------------------------------------

// GetTopRiskyCustomers returns the top N riskiest customers in the period.
func (r *AnalyticsRepository) GetTopRiskyCustomers(ctx context.Context, from, to time.Time, limit int) ([]*domain.RiskyCustomer, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	q := fmt.Sprintf(`
SELECT
    customer_id,
    COUNT(*)                                                    AS alert_count,
    COALESCE(
        COUNT(*) FILTER (WHERE priority >= 3)::float / NULLIF(COUNT(*), 0),
        0)                                                      AS fraud_rate,
    COALESCE(AVG(risk_score), 0)                                AS avg_risk_score,
    MAX(created_at)                                             AS last_alert_at
FROM fraud_alerts
WHERE created_at BETWEEN $1 AND $2
GROUP BY customer_id
ORDER BY alert_count DESC, fraud_rate DESC
LIMIT %d`, limit)

	rows, err := r.db.Query(ctx, q, from, to)
	if err != nil {
		return nil, fmt.Errorf("top risky customers query: %w", err)
	}
	defer rows.Close()

	var customers []*domain.RiskyCustomer
	for rows.Next() {
		c := &domain.RiskyCustomer{}
		if err := rows.Scan(&c.CustomerID, &c.AlertCount, &c.FraudRate, &c.AvgRiskScore, &c.LastAlertAt); err != nil {
			return nil, fmt.Errorf("scan risky customer: %w", err)
		}
		customers = append(customers, c)
	}
	return customers, rows.Err()
}

// ---------------------------------------------------------------------------
// GetModelPerformance — precision/recall from alert outcome labels
// ---------------------------------------------------------------------------

// GetModelPerformance computes prediction quality metrics for a model version.
// TP = RESOLVED alerts; FP = FALSE_POSITIVE alerts. TN/FN are not observable.
func (r *AnalyticsRepository) GetModelPerformance(ctx context.Context, modelVersion string, from, to time.Time) (*domain.ModelPerformance, error) {
	q := `
SELECT
    COUNT(*)                                                    AS total,
    COUNT(*) FILTER (WHERE status = 'RESOLVED')                 AS tp,
    COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')           AS fp,
    COALESCE(AVG(fraud_probability) FILTER (WHERE status = 'RESOLVED'), 0)       AS avg_prob_tp,
    COALESCE(AVG(fraud_probability) FILTER (WHERE status = 'FALSE_POSITIVE'), 0) AS avg_prob_fp
FROM fraud_alerts
WHERE created_at BETWEEN $1 AND $2`

	args := []any{from, to}
	if modelVersion != "" {
		q += " AND model_version = $3"
		args = append(args, modelVersion)
	}

	var total, tp, fp int64
	var avgProbTP, avgProbFP float64
	if err := r.db.QueryRow(ctx, q, args...).Scan(&total, &tp, &fp, &avgProbTP, &avgProbFP); err != nil {
		return nil, fmt.Errorf("model performance query: %w", err)
	}

	// Resolve model version label
	if modelVersion == "" {
		modelVersion = "all"
	}

	perf := &domain.ModelPerformance{
		ModelVersion:     modelVersion,
		TotalPredictions: total,
		TruePositives:    tp,
		FalsePositives:   fp,
	}

	if tp+fp > 0 {
		perf.Precision = float64(tp) / float64(tp+fp)
	}
	// Recall approximation: treat unresolved alerts as potential misses
	unresolved := total - tp - fp
	if tp+fp+unresolved > 0 {
		perf.Recall = float64(tp) / float64(tp+fp+unresolved)
	}
	if perf.Precision+perf.Recall > 0 {
		perf.F1Score = 2 * perf.Precision * perf.Recall / (perf.Precision + perf.Recall)
	}
	// AUC-ROC approximation: (avg_prob_tp + (1 - avg_prob_fp)) / 2
	if tp > 0 || fp > 0 {
		perf.AUCROC = (avgProbTP + (1 - avgProbFP)) / 2
	}

	return perf, nil
}

// ---------------------------------------------------------------------------
// GetAlertMetrics — detailed alert lifecycle statistics
// ---------------------------------------------------------------------------

// GetAlertMetrics returns rich lifecycle statistics for the given period.
func (r *AnalyticsRepository) GetAlertMetrics(ctx context.Context, from, to time.Time) (*domain.AlertMetrics, error) {
	const q = `
SELECT
    COUNT(*)                                                            AS total,
    COUNT(*) FILTER (WHERE status = 'OPEN')                            AS open_cnt,
    COUNT(*) FILTER (WHERE status = 'RESOLVED')                        AS resolved_cnt,
    COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')                  AS fp_cnt,
    COUNT(*) FILTER (WHERE status = 'ESCALATED')                       AS escalated_cnt,
    COALESCE(AVG(
        EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60
    ) FILTER (WHERE resolved_at IS NOT NULL), 0)                       AS avg_res_min,
    COALESCE(
        COUNT(*) FILTER (WHERE status = 'ESCALATED')::float / NULLIF(COUNT(*), 0),
        0)                                                             AS escalation_rate,
    COALESCE(
        COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')::float /
        NULLIF(COUNT(*) FILTER (WHERE status IN ('RESOLVED','FALSE_POSITIVE')), 0),
        0)                                                             AS fp_rate,
    COUNT(*) FILTER (WHERE priority = 1)                               AS low_cnt,
    COUNT(*) FILTER (WHERE priority = 2)                               AS medium_cnt,
    COUNT(*) FILTER (WHERE priority = 3)                               AS high_cnt,
    COUNT(*) FILTER (WHERE priority = 4)                               AS critical_cnt
FROM fraud_alerts
WHERE created_at BETWEEN $1 AND $2`

	var (
		total, open, resolved, fp, escalated                  int
		avgResMin, escalationRate, fpRate                     float64
		lowCnt, mediumCnt, highCnt, criticalCnt               int
	)
	err := r.db.QueryRow(ctx, q, from, to).Scan(
		&total, &open, &resolved, &fp, &escalated,
		&avgResMin, &escalationRate, &fpRate,
		&lowCnt, &mediumCnt, &highCnt, &criticalCnt,
	)
	if err != nil {
		return nil, fmt.Errorf("alert metrics query: %w", err)
	}

	return &domain.AlertMetrics{
		TotalAlerts:       total,
		OpenAlerts:        open,
		ResolvedAlerts:    resolved,
		FalsePositives:    fp,
		EscalatedAlerts:   escalated,
		AvgResolutionMin:  avgResMin,
		EscalationRate:    escalationRate,
		FalsePositiveRate: fpRate,
		ByPriority: map[string]int{
			"LOW":      lowCnt,
			"MEDIUM":   mediumCnt,
			"HIGH":     highCnt,
			"CRITICAL": criticalCnt,
		},
	}, nil
}

// Ping checks the database connection.
func (r *AnalyticsRepository) Ping(ctx context.Context) error {
	return r.db.Ping(ctx)
}
