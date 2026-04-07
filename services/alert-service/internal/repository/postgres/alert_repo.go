// Package postgres implements the PostgreSQL persistence layer for alerts.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/fraud-detection/alert-service/internal/domain"
)

// AlertRepository handles all PostgreSQL operations for alerts.
type AlertRepository struct {
	db *pgxpool.Pool
}

// New creates a new AlertRepository backed by the given connection pool.
func New(db *pgxpool.Pool) *AlertRepository {
	return &AlertRepository{db: db}
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
// Create
// ---------------------------------------------------------------------------

const insertAlertSQL = `
INSERT INTO fraud_alerts (
    alert_id, customer_id, tx_hash, fraud_probability, risk_score,
    priority, status, model_version, shap_explanation_json,
    features_snapshot_json, assignee_id, assigned_at, escalated_at,
    resolved_at, resolution_notes, blockchain_tx_id, dedup_hash,
    created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
)`

// Create inserts a new alert. Returns ErrDuplicateAlert on unique constraint violation.
func (r *AlertRepository) Create(ctx context.Context, a *domain.Alert) error {
	_, err := r.db.Exec(ctx, insertAlertSQL,
		a.AlertID, a.CustomerID, a.TxHash, a.FraudProbability, a.RiskScore,
		int(a.Priority), string(a.Status), a.ModelVersion, a.SHAPExplanationJSON,
		a.FeaturesSnapshotJSON, nullableString(a.AssigneeID), a.AssignedAt, a.EscalatedAt,
		a.ResolvedAt, a.ResolutionNotes, a.BlockchainTxID, a.DedupHash,
		a.CreatedAt, a.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKey(err) {
			return domain.ErrDuplicateAlert
		}
		return fmt.Errorf("insert alert: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

const selectAlertSQL = `
SELECT alert_id, customer_id, tx_hash, fraud_probability, risk_score,
       priority, status, model_version, shap_explanation_json,
       features_snapshot_json, COALESCE(assignee_id,''), assigned_at, escalated_at,
       resolved_at, COALESCE(resolution_notes,''), COALESCE(blockchain_tx_id,''),
       dedup_hash, created_at, updated_at
FROM fraud_alerts
WHERE alert_id = $1`

// GetByID retrieves a single alert by its primary key.
func (r *AlertRepository) GetByID(ctx context.Context, alertID string) (*domain.Alert, error) {
	row := r.db.QueryRow(ctx, selectAlertSQL, alertID)
	a, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrAlertNotFound
		}
		return nil, fmt.Errorf("get alert %s: %w", alertID, err)
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// List returns a page of alerts matching the given filters.
func (r *AlertRepository) List(ctx context.Context, f domain.AlertFilters) ([]*domain.Alert, int, error) {
	where, args := buildWhere(f)

	sortCol := safeSortColumn(f.SortBy)
	dir := "DESC"
	if f.Ascending {
		dir = "ASC"
	}

	pageSize := f.PageSize
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	// Count total matching rows
	countSQL := "SELECT COUNT(*) FROM fraud_alerts" + where
	var total int
	if err := r.db.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count alerts: %w", err)
	}

	// Fetch page
	query := fmt.Sprintf(`
SELECT alert_id, customer_id, tx_hash, fraud_probability, risk_score,
       priority, status, model_version, shap_explanation_json,
       features_snapshot_json, COALESCE(assignee_id,''), assigned_at, escalated_at,
       resolved_at, COALESCE(resolution_notes,''), COALESCE(blockchain_tx_id,''),
       dedup_hash, created_at, updated_at
FROM fraud_alerts%s
ORDER BY %s %s
LIMIT %d OFFSET %d`, where, sortCol, dir, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan alert row: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, total, rows.Err()
}

// GetByCustomer returns the alert history for a specific customer, newest first.
func (r *AlertRepository) GetByCustomer(ctx context.Context, customerID string, limit, offset int) ([]*domain.Alert, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	const q = `
SELECT alert_id, customer_id, tx_hash, fraud_probability, risk_score,
       priority, status, model_version, shap_explanation_json,
       features_snapshot_json, COALESCE(assignee_id,''), assigned_at, escalated_at,
       resolved_at, COALESCE(resolution_notes,''), COALESCE(blockchain_tx_id,''),
       dedup_hash, created_at, updated_at
FROM fraud_alerts
WHERE customer_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, q, customerID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("get customer alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("scan customer alert: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// UpdateStatus transitions an alert to a new status and records the history.
// Returns ErrInvalidTransition if the transition is not permitted.
func (r *AlertRepository) UpdateStatus(ctx context.Context, alertID, changedBy, notes string, newStatus domain.AlertStatus) (*domain.Alert, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	// Lock the row for update
	var current domain.Alert
	var priority int
	var status string
	err = tx.QueryRow(ctx, `
SELECT alert_id, status, priority, customer_id, tx_hash, fraud_probability,
       risk_score, model_version, shap_explanation_json, features_snapshot_json,
       COALESCE(assignee_id,''), assigned_at, escalated_at, resolved_at,
       COALESCE(resolution_notes,''), COALESCE(blockchain_tx_id,''),
       dedup_hash, created_at, updated_at
FROM fraud_alerts WHERE alert_id = $1 FOR UPDATE`, alertID).
		Scan(&current.AlertID, &status, &priority,
			&current.CustomerID, &current.TxHash, &current.FraudProbability,
			&current.RiskScore, &current.ModelVersion, &current.SHAPExplanationJSON,
			&current.FeaturesSnapshotJSON, &current.AssigneeID, &current.AssignedAt,
			&current.EscalatedAt, &current.ResolvedAt, &current.ResolutionNotes,
			&current.BlockchainTxID, &current.DedupHash, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrAlertNotFound
		}
		return nil, fmt.Errorf("lock alert: %w", err)
	}
	current.Status = domain.AlertStatus(status)
	current.Priority = domain.AlertPriority(priority)

	if err = domain.ValidateTransition(current.Status, newStatus); err != nil {
		return nil, domain.ErrInvalidTransition
	}

	// Determine timestamp fields to update
	now := time.Now().UTC()
	var resolvedAt *time.Time
	var escalatedAt *time.Time

	switch newStatus {
	case domain.StatusResolved, domain.StatusFalsePositive:
		resolvedAt = &now
	case domain.StatusEscalated:
		escalatedAt = &now
	}

	_, err = tx.Exec(ctx, `
UPDATE fraud_alerts
SET status=$1, resolution_notes=CASE WHEN $2!='' THEN $2 ELSE resolution_notes END,
    resolved_at=COALESCE($3, resolved_at),
    escalated_at=COALESCE($4, escalated_at),
    updated_at=NOW()
WHERE alert_id=$5`,
		string(newStatus), notes, resolvedAt, escalatedAt, alertID)
	if err != nil {
		return nil, fmt.Errorf("update status: %w", err)
	}

	_, err = tx.Exec(ctx, `
INSERT INTO alert_status_history (alert_id, from_status, to_status, changed_by, notes)
VALUES ($1,$2,$3,$4,$5)`,
		alertID, string(current.Status), string(newStatus), changedBy, notes)
	if err != nil {
		return nil, fmt.Errorf("insert history: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// Return updated record
	return r.GetByID(ctx, alertID)
}

// Assign sets the assignee for an alert.
func (r *AlertRepository) Assign(ctx context.Context, alertID, assigneeID string) (*domain.Alert, error) {
	now := time.Now().UTC()
	tag, err := r.db.Exec(ctx, `
UPDATE fraud_alerts SET assignee_id=$1, assigned_at=$2, updated_at=NOW()
WHERE alert_id=$3`, assigneeID, now, alertID)
	if err != nil {
		return nil, fmt.Errorf("assign alert: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, domain.ErrAlertNotFound
	}
	return r.GetByID(ctx, alertID)
}

// SetBlockchainTxID stores the blockchain audit trail reference.
func (r *AlertRepository) SetBlockchainTxID(ctx context.Context, alertID, txID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE fraud_alerts SET blockchain_tx_id=$1, updated_at=NOW() WHERE alert_id=$2`,
		txID, alertID)
	return err
}

// ---------------------------------------------------------------------------
// Escalation candidates
// ---------------------------------------------------------------------------

// GetEscalationCandidates returns CRITICAL/HIGH alerts that are OPEN or
// INVESTIGATING, have not yet been escalated, and have been open longer than
// the given threshold.
func (r *AlertRepository) GetEscalationCandidates(ctx context.Context, threshold time.Duration) ([]*domain.Alert, error) {
	cutoff := time.Now().UTC().Add(-threshold)
	const q = `
SELECT alert_id, customer_id, tx_hash, fraud_probability, risk_score,
       priority, status, model_version, shap_explanation_json,
       features_snapshot_json, COALESCE(assignee_id,''), assigned_at, escalated_at,
       resolved_at, COALESCE(resolution_notes,''), COALESCE(blockchain_tx_id,''),
       dedup_hash, created_at, updated_at
FROM fraud_alerts
WHERE status IN ('OPEN','INVESTIGATING')
  AND escalated_at IS NULL
  AND priority >= 3
  AND created_at <= $1
ORDER BY priority DESC, created_at ASC`

	rows, err := r.db.Query(ctx, q, cutoff)
	if err != nil {
		return nil, fmt.Errorf("escalation candidates: %w", err)
	}
	defer rows.Close()

	var alerts []*domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

// LogNotification persists a notification attempt record.
func (r *AlertRepository) LogNotification(ctx context.Context,
	alertID, channel, recipient string, success bool, providerMsgID, errMsg string,
) error {
	_, err := r.db.Exec(ctx, `
INSERT INTO alert_notifications (alert_id, channel, recipient, success, provider_msg_id, error_message)
VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''))`,
		alertID, channel, recipient, success, providerMsgID, errMsg)
	if err != nil {
		log.Error().Err(err).Str("alert_id", alertID).Str("channel", channel).Msg("log notification failed")
	}
	return err
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// GetStats returns aggregate alert statistics for the given period label.
func (r *AlertRepository) GetStats(ctx context.Context, period string) (*domain.AlertStats, error) {
	var since time.Time
	switch period {
	case "24h":
		since = time.Now().UTC().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().UTC().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().UTC().Add(-30 * 24 * time.Hour)
	default:
		since = time.Now().UTC().Add(-24 * time.Hour)
		period = "24h"
	}

	const q = `
SELECT
    COUNT(*)                                                           AS total,
    COUNT(*) FILTER (WHERE status='OPEN')                              AS open_cnt,
    COUNT(*) FILTER (WHERE priority=4)                                 AS critical_cnt,
    COUNT(*) FILTER (WHERE priority=3)                                 AS high_cnt,
    COUNT(*) FILTER (WHERE priority=2)                                 AS medium_cnt,
    COUNT(*) FILTER (WHERE priority=1)                                 AS low_cnt,
    COUNT(*) FILTER (WHERE status='RESOLVED')                          AS resolved_cnt,
    COUNT(*) FILTER (WHERE status='FALSE_POSITIVE')                    AS fp_cnt,
    COUNT(*) FILTER (WHERE status='ESCALATED')                         AS escalated_cnt,
    COALESCE(AVG(fraud_probability),0)                                 AS avg_prob,
    COALESCE(
        COUNT(*) FILTER (WHERE status='FALSE_POSITIVE')::float /
        NULLIF(COUNT(*) FILTER (WHERE status IN ('RESOLVED','FALSE_POSITIVE')),0),
        0)                                                             AS fp_rate,
    COALESCE(AVG(
        EXTRACT(EPOCH FROM (resolved_at - created_at))/60)
        FILTER (WHERE resolved_at IS NOT NULL), 0)                    AS avg_res_min,
    COALESCE(
        COUNT(*) FILTER (WHERE status='ESCALATED')::float /
        NULLIF(COUNT(*),0), 0)                                        AS escalation_rate
FROM fraud_alerts
WHERE created_at >= $1`

	s := &domain.AlertStats{Period: period}
	err := r.db.QueryRow(ctx, q, since).Scan(
		&s.TotalAlerts, &s.OpenAlerts, &s.CriticalAlerts, &s.HighAlerts,
		&s.MediumAlerts, &s.LowAlerts, &s.ResolvedAlerts, &s.FalsePositives,
		&s.EscalatedAlerts, &s.AvgFraudProbability, &s.FalsePositiveRate,
		&s.AvgResolutionTimeMin, &s.EscalationRate,
	)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}
	return s, nil
}

// Ping checks the database connection.
func (r *AlertRepository) Ping(ctx context.Context) error {
	return r.db.Ping(ctx)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanAlert(s scanner) (*domain.Alert, error) {
	var a domain.Alert
	var priority int
	var status string
	err := s.Scan(
		&a.AlertID, &a.CustomerID, &a.TxHash, &a.FraudProbability, &a.RiskScore,
		&priority, &status, &a.ModelVersion, &a.SHAPExplanationJSON,
		&a.FeaturesSnapshotJSON, &a.AssigneeID, &a.AssignedAt, &a.EscalatedAt,
		&a.ResolvedAt, &a.ResolutionNotes, &a.BlockchainTxID,
		&a.DedupHash, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.Priority = domain.AlertPriority(priority)
	a.Status = domain.AlertStatus(status)
	return &a, nil
}

func buildWhere(f domain.AlertFilters) (string, []any) {
	var clauses []string
	var args []any
	n := 1

	if f.Status != "" {
		clauses = append(clauses, fmt.Sprintf("status=$%d", n))
		args = append(args, string(f.Status))
		n++
	}
	if f.Priority != 0 {
		clauses = append(clauses, fmt.Sprintf("priority=$%d", n))
		args = append(args, int(f.Priority))
		n++
	}
	if f.AssigneeID != "" {
		clauses = append(clauses, fmt.Sprintf("assignee_id=$%d", n))
		args = append(args, f.AssigneeID)
		n++
	}
	if f.MinFraudProb > 0 {
		clauses = append(clauses, fmt.Sprintf("fraud_probability>=$%d", n))
		args = append(args, f.MinFraudProb)
		n++
	}
	if !f.StartTime.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at>=$%d", n))
		args = append(args, f.StartTime)
		n++
	}
	if !f.EndTime.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at<=$%d", n))
		args = append(args, f.EndTime)
		n++
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func safeSortColumn(col string) string {
	switch col {
	case "fraud_probability":
		return "fraud_probability"
	case "risk_score":
		return "risk_score"
	case "priority":
		return "priority"
	default:
		return "created_at"
	}
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isDuplicateKey(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}
	return false
}
