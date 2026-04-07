// Package postgres implements the PostgreSQL persistence layer for the Case Service.
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

	"github.com/fraud-detection/case-service/internal/domain"
)

// CaseRepository handles all PostgreSQL operations for cases.
type CaseRepository struct {
	db *pgxpool.Pool
}

// New creates a CaseRepository backed by the given connection pool.
func New(db *pgxpool.Pool) *CaseRepository {
	return &CaseRepository{db: db}
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
// Cases
// ---------------------------------------------------------------------------

const insertCaseSQL = `
INSERT INTO investigation_cases (
    case_id, alert_id, customer_id, tx_hash, title, description,
    status, priority, assignee_id, assigned_at, fraud_probability,
    risk_score, sar_required, sar_s3_key, sar_generated_at,
    blockchain_tx_id, resolution_summary, closed_at, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
)`

// CreateCase inserts a new investigation case.
// Returns ErrDuplicateCase if a case already exists for this alert_id.
func (r *CaseRepository) CreateCase(ctx context.Context, c *domain.Case) error {
	_, err := r.db.Exec(ctx, insertCaseSQL,
		c.CaseID, c.AlertID, c.CustomerID, c.TxHash, c.Title, c.Description,
		string(c.Status), int(c.Priority), nullableStr(c.AssigneeID), c.AssignedAt,
		c.FraudProbability, c.RiskScore, c.SARRequired, c.SARS3Key, c.SARGeneratedAt,
		c.BlockchainTxID, c.ResolutionSummary, c.ClosedAt, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKey(err) {
			return domain.ErrDuplicateCase
		}
		return fmt.Errorf("insert case: %w", err)
	}
	return nil
}

// GetCaseByID retrieves a case by its primary key.
func (r *CaseRepository) GetCaseByID(ctx context.Context, caseID string) (*domain.Case, error) {
	const q = `SELECT ` + caseColumns + ` FROM investigation_cases WHERE case_id = $1`
	row := r.db.QueryRow(ctx, q, caseID)
	c, err := scanCase(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrCaseNotFound
		}
		return nil, fmt.Errorf("get case %s: %w", caseID, err)
	}
	return c, nil
}

// GetCaseByAlertID retrieves a case by the originating alert ID.
func (r *CaseRepository) GetCaseByAlertID(ctx context.Context, alertID string) (*domain.Case, error) {
	const q = `SELECT ` + caseColumns + ` FROM investigation_cases WHERE alert_id = $1`
	row := r.db.QueryRow(ctx, q, alertID)
	c, err := scanCase(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrCaseNotFound
		}
		return nil, fmt.Errorf("get case by alert %s: %w", alertID, err)
	}
	return c, nil
}

// ListCases returns a filtered, paginated list of cases and total count.
func (r *CaseRepository) ListCases(ctx context.Context, f domain.CaseFilters) ([]*domain.Case, int, error) {
	where, args := buildCaseWhere(f)
	sortCol := safeSortCol(f.SortBy)
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

	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM investigation_cases"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count cases: %w", err)
	}

	query := fmt.Sprintf(`SELECT `+caseColumns+` FROM investigation_cases%s ORDER BY %s %s LIMIT %d OFFSET %d`,
		where, sortCol, dir, pageSize, offset)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list cases: %w", err)
	}
	defer rows.Close()

	var cases []*domain.Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, 0, err
		}
		cases = append(cases, c)
	}
	return cases, total, rows.Err()
}

// UpdateCaseStatus transitions a case to a new status inside a transaction.
// Records the action and optionally sets resolved/closed timestamps.
func (r *CaseRepository) UpdateCaseStatus(ctx context.Context, caseID, updatedBy, notes string, newStatus domain.CaseStatus, resolutionSummary string) (*domain.Case, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	// Lock row
	var c domain.Case
	var status string
	var priority int
	err = tx.QueryRow(ctx, `SELECT case_id, status, priority, sar_required FROM investigation_cases WHERE case_id = $1 FOR UPDATE`, caseID).
		Scan(&c.CaseID, &status, &priority, &c.SARRequired)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrCaseNotFound
		}
		return nil, fmt.Errorf("lock case: %w", err)
	}
	c.Status = domain.CaseStatus(status)
	c.Priority = domain.CasePriority(priority)

	if err = domain.ValidateTransition(c.Status, newStatus); err != nil {
		return nil, domain.ErrInvalidTransition
	}

	now := time.Now().UTC()
	var closedAt *time.Time
	if newStatus == domain.CaseStatusClosed {
		closedAt = &now
	}

	_, err = tx.Exec(ctx, `
UPDATE investigation_cases
SET status=$1,
    resolution_summary = CASE WHEN $2 != '' THEN $2 ELSE resolution_summary END,
    closed_at = COALESCE($3, closed_at),
    updated_at = NOW()
WHERE case_id=$4`,
		string(newStatus), resolutionSummary, closedAt, caseID)
	if err != nil {
		return nil, fmt.Errorf("update case status: %w", err)
	}

	_, err = tx.Exec(ctx, `
INSERT INTO case_actions (case_id, investigator_id, action, notes)
VALUES ($1,$2,'STATUS_CHANGED',$3)`,
		caseID, updatedBy, notes)
	if err != nil {
		return nil, fmt.Errorf("insert action: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return r.GetCaseByID(ctx, caseID)
}

// AssignCase sets the assignee for a case.
func (r *CaseRepository) AssignCase(ctx context.Context, caseID, assigneeID, assignedBy string) (*domain.Case, error) {
	now := time.Now().UTC()
	tag, err := r.db.Exec(ctx, `
UPDATE investigation_cases SET assignee_id=$1, assigned_at=$2, updated_at=NOW()
WHERE case_id=$3`, assigneeID, now, caseID)
	if err != nil {
		return nil, fmt.Errorf("assign case: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, domain.ErrCaseNotFound
	}
	_, _ = r.db.Exec(ctx, `
INSERT INTO case_actions (case_id, investigator_id, action, notes)
VALUES ($1,$2,'ASSIGNED',$3)`,
		caseID, assignedBy, fmt.Sprintf("assigned to %s", assigneeID))
	return r.GetCaseByID(ctx, caseID)
}

// SetSAR stores the S3 key of the generated SAR PDF.
func (r *CaseRepository) SetSAR(ctx context.Context, caseID, s3Key, generatedBy string) (*domain.Case, error) {
	now := time.Now().UTC()
	tag, err := r.db.Exec(ctx, `
UPDATE investigation_cases
SET sar_s3_key=$1, sar_generated_at=$2, status='PENDING_SAR', updated_at=NOW()
WHERE case_id=$3 AND sar_s3_key=''`, s3Key, now, caseID)
	if err != nil {
		return nil, fmt.Errorf("set sar: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either not found or SAR already set
		existing, getErr := r.GetCaseByID(ctx, caseID)
		if getErr != nil {
			return nil, domain.ErrCaseNotFound
		}
		if existing.SARS3Key != "" {
			return nil, domain.ErrSARAlreadyExists
		}
		return nil, domain.ErrCaseNotFound
	}
	_, _ = r.db.Exec(ctx, `
INSERT INTO case_actions (case_id, investigator_id, action, notes)
VALUES ($1,$2,'SAR_GENERATED',$3)`,
		caseID, generatedBy, fmt.Sprintf("SAR uploaded to S3: %s", s3Key))
	return r.GetCaseByID(ctx, caseID)
}

// SetBlockchainTxID stores the Fabric transaction ID for audit.
func (r *CaseRepository) SetBlockchainTxID(ctx context.Context, actionID, txID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE case_actions SET blockchain_tx_id=$1 WHERE action_id=$2`, txID, actionID)
	return err
}

// UpdateCaseBlockchainTxID stores the Fabric TX on the case record.
func (r *CaseRepository) UpdateCaseBlockchainTxID(ctx context.Context, caseID, txID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE investigation_cases SET blockchain_tx_id=$1, updated_at=NOW() WHERE case_id=$2`, txID, caseID)
	return err
}

// GetInvestigatorWorkload returns the count of OPEN+IN_REVIEW cases per investigator.
func (r *CaseRepository) GetInvestigatorWorkload(ctx context.Context, investigatorIDs []string) ([]*domain.InvestigatorWorkload, error) {
	if len(investigatorIDs) == 0 {
		const q = `
SELECT assignee_id, COUNT(*) FROM investigation_cases
WHERE assignee_id IS NOT NULL AND status IN ('OPEN','IN_REVIEW','PENDING_SAR')
GROUP BY assignee_id`
		rows, err := r.db.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanWorkloads(rows)
	}

	placeholders := make([]string, len(investigatorIDs))
	args := make([]any, len(investigatorIDs))
	for i, id := range investigatorIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	q := fmt.Sprintf(`
SELECT assignee_id, COUNT(*) FROM investigation_cases
WHERE assignee_id IN (%s) AND status IN ('OPEN','IN_REVIEW','PENDING_SAR')
GROUP BY assignee_id`, strings.Join(placeholders, ","))
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWorkloads(rows)
}

// GetStats returns aggregate case statistics for the given period.
func (r *CaseRepository) GetStats(ctx context.Context, period string) (*domain.CaseStats, error) {
	var since time.Time
	switch period {
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
    COUNT(*)                                                              AS total,
    COUNT(*) FILTER (WHERE status='OPEN')                                AS open_cnt,
    COUNT(*) FILTER (WHERE status='IN_REVIEW')                           AS in_review_cnt,
    COUNT(*) FILTER (WHERE status='PENDING_SAR')                         AS pending_sar_cnt,
    COUNT(*) FILTER (WHERE status='CLOSED')                              AS closed_cnt,
    COUNT(*) FILTER (WHERE priority=4)                                   AS critical_cnt,
    COUNT(*) FILTER (WHERE sar_s3_key != '')                             AS sar_generated_cnt,
    COALESCE(AVG(
        EXTRACT(EPOCH FROM (closed_at - created_at))/3600)
        FILTER (WHERE closed_at IS NOT NULL), 0)                         AS avg_resolution_hours
FROM investigation_cases
WHERE created_at >= $1`

	s := &domain.CaseStats{Period: period}
	err := r.db.QueryRow(ctx, q, since).Scan(
		&s.TotalCases, &s.OpenCases, &s.InReviewCases, &s.PendingSARCases,
		&s.ClosedCases, &s.CriticalCases, &s.SARGenerated, &s.AvgResolutionHours,
	)
	if err != nil {
		return nil, fmt.Errorf("get case stats: %w", err)
	}
	return s, nil
}

// Ping checks the database connection.
func (r *CaseRepository) Ping(ctx context.Context) error {
	return r.db.Ping(ctx)
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

// AddEvidence inserts a new evidence record for a case.
func (r *CaseRepository) AddEvidence(ctx context.Context, e *domain.Evidence) error {
	_, err := r.db.Exec(ctx, `
INSERT INTO case_evidence (evidence_id, case_id, uploaded_by, file_name, file_size, content_type, s3_key, evidence_type, notes, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		e.EvidenceID, e.CaseID, e.UploadedBy, e.FileName, e.FileSize,
		e.ContentType, e.S3Key, string(e.EvidenceType), e.Notes, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert evidence: %w", err)
	}
	_, _ = r.db.Exec(ctx, `
INSERT INTO case_actions (case_id, investigator_id, action, notes)
VALUES ($1,$2,'EVIDENCE_ADDED',$3)`,
		e.CaseID, e.UploadedBy, fmt.Sprintf("evidence added: %s", e.FileName))
	return nil
}

// GetEvidence returns all evidence records for a case (or a single record by evidenceID).
func (r *CaseRepository) GetEvidence(ctx context.Context, caseID, evidenceID string) ([]*domain.Evidence, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if evidenceID != "" {
		rows, err = r.db.Query(ctx, `
SELECT evidence_id, case_id, uploaded_by, file_name, file_size, content_type,
       s3_key, evidence_type, COALESCE(notes,''), created_at
FROM case_evidence WHERE case_id=$1 AND evidence_id=$2`, caseID, evidenceID)
	} else {
		rows, err = r.db.Query(ctx, `
SELECT evidence_id, case_id, uploaded_by, file_name, file_size, content_type,
       s3_key, evidence_type, COALESCE(notes,''), created_at
FROM case_evidence WHERE case_id=$1 ORDER BY created_at DESC`, caseID)
	}
	if err != nil {
		return nil, fmt.Errorf("get evidence: %w", err)
	}
	defer rows.Close()

	var evs []*domain.Evidence
	for rows.Next() {
		var e domain.Evidence
		var evType string
		if err := rows.Scan(&e.EvidenceID, &e.CaseID, &e.UploadedBy, &e.FileName,
			&e.FileSize, &e.ContentType, &e.S3Key, &evType, &e.Notes, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.EvidenceType = domain.EvidenceType(evType)
		evs = append(evs, &e)
	}
	return evs, rows.Err()
}

// DeleteEvidence removes an evidence record.
func (r *CaseRepository) DeleteEvidence(ctx context.Context, caseID, evidenceID, deletedBy string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM case_evidence WHERE case_id=$1 AND evidence_id=$2`, caseID, evidenceID)
	if err != nil {
		return fmt.Errorf("delete evidence: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrEvidenceNotFound
	}
	_, _ = r.db.Exec(ctx, `
INSERT INTO case_actions (case_id, investigator_id, action, notes)
VALUES ($1,$2,'EVIDENCE_DELETED',$3)`,
		caseID, deletedBy, fmt.Sprintf("evidence %s deleted", evidenceID))
	return nil
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

// GetActions returns the action audit trail for a case.
func (r *CaseRepository) GetActions(ctx context.Context, caseID string) ([]*domain.CaseAction, error) {
	rows, err := r.db.Query(ctx, `
SELECT action_id, case_id, investigator_id, action, COALESCE(notes,''),
       COALESCE(blockchain_tx_id,''), performed_at
FROM case_actions WHERE case_id=$1 ORDER BY performed_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("get actions: %w", err)
	}
	defer rows.Close()

	var actions []*domain.CaseAction
	for rows.Next() {
		var a domain.CaseAction
		if err := rows.Scan(&a.ActionID, &a.CaseID, &a.InvestigatorID, &a.Action,
			&a.Notes, &a.BlockchainTxID, &a.PerformedAt); err != nil {
			return nil, err
		}
		actions = append(actions, &a)
	}
	return actions, rows.Err()
}

// LogAction inserts a standalone action record and returns its ID.
func (r *CaseRepository) LogAction(ctx context.Context, a *domain.CaseAction) error {
	_, err := r.db.Exec(ctx, `
INSERT INTO case_actions (action_id, case_id, investigator_id, action, notes, performed_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())`,
		a.CaseID, a.InvestigatorID, a.Action, a.Notes)
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const caseColumns = `
    case_id, alert_id, customer_id, tx_hash, title, description,
    status, priority, COALESCE(assignee_id,''), assigned_at,
    fraud_probability, risk_score, sar_required, COALESCE(sar_s3_key,''),
    sar_generated_at, COALESCE(blockchain_tx_id,''), COALESCE(resolution_summary,''),
    closed_at, created_at, updated_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanCase(s scanner) (*domain.Case, error) {
	var c domain.Case
	var status string
	var priority int
	err := s.Scan(
		&c.CaseID, &c.AlertID, &c.CustomerID, &c.TxHash, &c.Title, &c.Description,
		&status, &priority, &c.AssigneeID, &c.AssignedAt,
		&c.FraudProbability, &c.RiskScore, &c.SARRequired, &c.SARS3Key,
		&c.SARGeneratedAt, &c.BlockchainTxID, &c.ResolutionSummary,
		&c.ClosedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.Status = domain.CaseStatus(status)
	c.Priority = domain.CasePriority(priority)
	return &c, nil
}

func scanWorkloads(rows pgx.Rows) ([]*domain.InvestigatorWorkload, error) {
	var out []*domain.InvestigatorWorkload
	for rows.Next() {
		var w domain.InvestigatorWorkload
		if err := rows.Scan(&w.InvestigatorID, &w.ActiveCases); err != nil {
			return nil, err
		}
		out = append(out, &w)
	}
	return out, rows.Err()
}

func buildCaseWhere(f domain.CaseFilters) (string, []any) {
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
	if f.CustomerID != "" {
		clauses = append(clauses, fmt.Sprintf("customer_id=$%d", n))
		args = append(args, f.CustomerID)
		n++
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func safeSortCol(col string) string {
	switch col {
	case "fraud_probability":
		return "fraud_probability"
	case "priority":
		return "priority"
	case "updated_at":
		return "updated_at"
	default:
		return "created_at"
	}
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isDuplicateKey(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
