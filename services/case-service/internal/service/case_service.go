// Package service contains the core Case Management Service business logic.
package service

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/fraud-detection/case-service/internal/pdf"
	s3store "github.com/fraud-detection/case-service/internal/s3"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ---------------------------------------------------------------------------
// Port interfaces
// ---------------------------------------------------------------------------

// CaseStore persists and retrieves cases from PostgreSQL.
type CaseStore interface {
	CreateCase(ctx context.Context, c *domain.Case) error
	GetCaseByID(ctx context.Context, caseID string) (*domain.Case, error)
	GetCaseByAlertID(ctx context.Context, alertID string) (*domain.Case, error)
	ListCases(ctx context.Context, f domain.CaseFilters) ([]*domain.Case, int, error)
	UpdateCaseStatus(ctx context.Context, caseID, updatedBy, notes string, newStatus domain.CaseStatus, resolutionSummary string) (*domain.Case, error)
	AssignCase(ctx context.Context, caseID, assigneeID, assignedBy string) (*domain.Case, error)
	SetSAR(ctx context.Context, caseID, s3Key, generatedBy string) (*domain.Case, error)
	UpdateCaseBlockchainTxID(ctx context.Context, caseID, txID string) error
	AddEvidence(ctx context.Context, e *domain.Evidence) error
	GetEvidence(ctx context.Context, caseID, evidenceID string) ([]*domain.Evidence, error)
	DeleteEvidence(ctx context.Context, caseID, evidenceID, deletedBy string) error
	GetActions(ctx context.Context, caseID string) ([]*domain.CaseAction, error)
	LogAction(ctx context.Context, a *domain.CaseAction) error
	GetInvestigatorWorkload(ctx context.Context, investigatorIDs []string) ([]*domain.InvestigatorWorkload, error)
	GetStats(ctx context.Context, period string) (*domain.CaseStats, error)
	Ping(ctx context.Context) error
}

// EvidenceStore manages S3 evidence storage.
type EvidenceStore interface {
	PresignPutURL(ctx context.Context, s3Key, contentType string) (string, error)
	PresignGetURL(ctx context.Context, s3Key string) (string, error)
	PutObject(ctx context.Context, s3Key, contentType string, data []byte) error
	DeleteObject(ctx context.Context, s3Key string) error
}

// BlockchainAuditor records actions on Hyperledger Fabric.
type BlockchainAuditor interface {
	RecordInvestigatorAction(ctx context.Context, actionID, investigatorID, caseID, action, notes string) (string, error)
	UpdateAlertStatus(ctx context.Context, alertID, status, investigatorID, notes string) (string, error)
	Ping(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// CaseService
// ---------------------------------------------------------------------------

// CaseService orchestrates the full case lifecycle.
type CaseService struct {
	store         CaseStore
	evidence      EvidenceStore
	blockchain    BlockchainAuditor
	sarGen        *pdf.Generator
	s3Bucket      string
	investigators []string
	sarThreshold  float64
	rrIdx         atomic.Uint64
}

// New creates a CaseService with all dependencies injected.
func New(
	store CaseStore,
	evidence EvidenceStore,
	blockchain BlockchainAuditor,
	sarGen *pdf.Generator,
	s3Bucket string,
	investigators []string,
	sarThreshold float64,
) *CaseService {
	return &CaseService{
		store:        store,
		evidence:     evidence,
		blockchain:   blockchain,
		sarGen:       sarGen,
		s3Bucket:     s3Bucket,
		investigators: investigators,
		sarThreshold: sarThreshold,
	}
}

// ---------------------------------------------------------------------------
// Case creation (Kafka auto-creation + gRPC direct)
// ---------------------------------------------------------------------------

// CreateCaseFromAlert auto-creates an investigation case from a Kafka alert event.
// Idempotent: returns the existing case if alert_id already has a case.
func (s *CaseService) CreateCaseFromAlert(ctx context.Context, event *domain.AlertEvent) error {
	// Check idempotency
	if existing, err := s.store.GetCaseByAlertID(ctx, event.AlertID); err == nil {
		log.Debug().Str("case_id", existing.CaseID).Str("alert_id", event.AlertID).
			Msg("case already exists for alert — skipping")
		return nil
	}

	priority := domain.PriorityFromFraudProb(event.FraudProbability)
	now := time.Now().UTC()
	c := &domain.Case{
		CaseID:           "case-" + uuid.NewString(),
		AlertID:          event.AlertID,
		CustomerID:       event.CustomerID,
		TxHash:           event.TxHash,
		Title:            fmt.Sprintf("[%s] Fraud Alert — Customer %s", priority.String(), event.CustomerID),
		Description:      fmt.Sprintf("Auto-created from fraud alert %s. Fraud probability: %.4f.", event.AlertID, event.FraudProbability),
		Status:           domain.CaseStatusOpen,
		Priority:         priority,
		FraudProbability: event.FraudProbability,
		RiskScore:        event.RiskScore,
		SARRequired:      event.FraudProbability >= s.sarThreshold,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// Auto-assign to least-loaded investigator
	if assignee := s.nextInvestigator(); assignee != "" {
		c.AssigneeID = assignee
		t := now
		c.AssignedAt = &t
	}

	if err := s.store.CreateCase(ctx, c); err != nil {
		if err == domain.ErrDuplicateCase {
			return nil // idempotent
		}
		return fmt.Errorf("create case: %w", err)
	}

	log.Info().
		Str("case_id", c.CaseID).
		Str("alert_id", event.AlertID).
		Str("assignee", c.AssigneeID).
		Str("priority", priority.String()).
		Bool("sar_required", c.SARRequired).
		Msg("investigation case auto-created")

	// Record on Fabric (non-fatal)
	s.auditAsync(ctx, c.CaseID, c.AssigneeID, "CASE_CREATED",
		fmt.Sprintf("case created from alert %s, fraud_prob=%.4f", event.AlertID, event.FraudProbability))

	return nil
}

// CreateCase creates a case directly (called via gRPC from other services).
func (s *CaseService) CreateCase(ctx context.Context, req *CreateCaseInput) (*domain.Case, error) {
	if req.AlertID == "" || req.CustomerID == "" {
		return nil, domain.ErrInvalidCase
	}

	// Check idempotency
	if existing, err := s.store.GetCaseByAlertID(ctx, req.AlertID); err == nil {
		return existing, nil
	}

	priority := req.Priority
	if priority == domain.CasePriorityUnspecified {
		priority = domain.PriorityFromFraudProb(req.FraudProbability)
	}
	now := time.Now().UTC()
	c := &domain.Case{
		CaseID:           "case-" + uuid.NewString(),
		AlertID:          req.AlertID,
		CustomerID:       req.CustomerID,
		TxHash:           req.TxHash,
		Title:            req.Title,
		Description:      req.Description,
		Status:           domain.CaseStatusOpen,
		Priority:         priority,
		FraudProbability: req.FraudProbability,
		RiskScore:        req.RiskScore,
		SARRequired:      req.FraudProbability >= s.sarThreshold,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if c.Title == "" {
		c.Title = fmt.Sprintf("[%s] Fraud Alert — Customer %s", priority.String(), req.CustomerID)
	}

	// Auto-assign if not specified
	if req.AssigneeID != "" {
		c.AssigneeID = req.AssigneeID
		t := now
		c.AssignedAt = &t
	} else if assignee := s.nextInvestigator(); assignee != "" {
		c.AssigneeID = assignee
		t := now
		c.AssignedAt = &t
	}

	if err := s.store.CreateCase(ctx, c); err != nil {
		if err == domain.ErrDuplicateCase {
			return s.store.GetCaseByAlertID(ctx, req.AlertID)
		}
		return nil, fmt.Errorf("create case: %w", err)
	}

	s.auditAsync(ctx, c.CaseID, c.AssigneeID, "CASE_CREATED", "case created via gRPC API")
	return c, nil
}

// CreateCaseInput is the input struct for direct case creation.
type CreateCaseInput struct {
	AlertID          string
	CustomerID       string
	TxHash           string
	Title            string
	Description      string
	Priority         domain.CasePriority
	FraudProbability float64
	RiskScore        float64
	AssigneeID       string
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetCase retrieves a case with its full action history.
func (s *CaseService) GetCase(ctx context.Context, caseID string) (*domain.Case, []*domain.CaseAction, error) {
	c, err := s.store.GetCaseByID(ctx, caseID)
	if err != nil {
		return nil, nil, err
	}
	actions, err := s.store.GetActions(ctx, caseID)
	if err != nil {
		log.Warn().Err(err).Str("case_id", caseID).Msg("failed to load actions")
	}
	return c, actions, nil
}

// ListCases returns filtered, paginated cases.
func (s *CaseService) ListCases(ctx context.Context, f domain.CaseFilters) ([]*domain.Case, int, error) {
	return s.store.ListCases(ctx, f)
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

// UpdateCaseStatus transitions a case to a new status and records the action.
func (s *CaseService) UpdateCaseStatus(ctx context.Context, caseID, updatedBy, notes string, newStatus domain.CaseStatus, resolutionSummary string) (*domain.Case, error) {
	updated, err := s.store.UpdateCaseStatus(ctx, caseID, updatedBy, notes, newStatus, resolutionSummary)
	if err != nil {
		return nil, err
	}

	// Record on Fabric
	action := fmt.Sprintf("STATUS_CHANGED_TO_%s", string(newStatus))
	s.auditAsync(ctx, caseID, updatedBy, action, notes)

	return updated, nil
}

// AssignCase assigns a case to an investigator.
func (s *CaseService) AssignCase(ctx context.Context, caseID, assigneeID, assignedBy string) (*domain.Case, error) {
	if assigneeID == "" {
		return nil, fmt.Errorf("%w: assignee_id required", domain.ErrInvalidCase)
	}
	updated, err := s.store.AssignCase(ctx, caseID, assigneeID, assignedBy)
	if err != nil {
		return nil, err
	}
	s.auditAsync(ctx, caseID, assignedBy, "ASSIGNED", fmt.Sprintf("assigned to %s", assigneeID))
	return updated, nil
}

// AutoAssign round-robins the next available investigator to a case.
func (s *CaseService) AutoAssign(ctx context.Context, caseID, assignedBy string) (*domain.Case, error) {
	if len(s.investigators) == 0 {
		return nil, domain.ErrNoInvestigators
	}
	assignee := s.nextInvestigator()
	return s.AssignCase(ctx, caseID, assignee, assignedBy)
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

// AddEvidence creates an evidence record and returns pre-signed S3 URLs.
// The caller uploads the file directly using the returned upload_url.
func (s *CaseService) AddEvidence(ctx context.Context, req *AddEvidenceInput) (*domain.Evidence, string, string, error) {
	// Verify case exists
	if _, err := s.store.GetCaseByID(ctx, req.CaseID); err != nil {
		return nil, "", "", err
	}

	evidenceID := uuid.NewString()
	s3Key := s3store.EvidenceKey(req.CaseID, evidenceID, req.FileName)

	// Generate pre-signed PUT URL for upload
	putURL, err := s.evidence.PresignPutURL(ctx, s3Key, req.ContentType)
	if err != nil {
		return nil, "", "", fmt.Errorf("presign PUT: %w", err)
	}

	// Generate pre-signed GET URL for download
	getURL, err := s.evidence.PresignGetURL(ctx, s3Key)
	if err != nil {
		return nil, "", "", fmt.Errorf("presign GET: %w", err)
	}

	e := &domain.Evidence{
		EvidenceID:   evidenceID,
		CaseID:       req.CaseID,
		UploadedBy:   req.UploadedBy,
		FileName:     req.FileName,
		FileSize:     req.FileSize,
		ContentType:  req.ContentType,
		S3Key:        s3Key,
		EvidenceType: req.EvidenceType,
		Notes:        req.Notes,
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.store.AddEvidence(ctx, e); err != nil {
		return nil, "", "", err
	}

	s.auditAsync(ctx, req.CaseID, req.UploadedBy, "EVIDENCE_ADDED",
		fmt.Sprintf("evidence %s (%s) added, s3_key=%s", req.FileName, req.ContentType, s3Key))

	return e, putURL, getURL, nil
}

// AddEvidenceInput is the input for evidence attachment.
type AddEvidenceInput struct {
	CaseID       string
	UploadedBy   string
	FileName     string
	FileSize     int64
	ContentType  string
	EvidenceType domain.EvidenceType
	Notes        string
}

// GetEvidence lists evidence for a case (or a specific item by evidenceID).
func (s *CaseService) GetEvidence(ctx context.Context, caseID, evidenceID string) ([]*domain.Evidence, []string, error) {
	evs, err := s.store.GetEvidence(ctx, caseID, evidenceID)
	if err != nil {
		return nil, nil, err
	}

	// Generate fresh GET URLs for each item
	urls := make([]string, len(evs))
	for i, e := range evs {
		url, presignErr := s.evidence.PresignGetURL(ctx, e.S3Key)
		if presignErr != nil {
			log.Warn().Err(presignErr).Str("s3_key", e.S3Key).Msg("failed to presign GET URL")
		}
		urls[i] = url
	}
	return evs, urls, nil
}

// DeleteEvidence removes evidence from S3 and the database.
func (s *CaseService) DeleteEvidence(ctx context.Context, caseID, evidenceID, deletedBy string) error {
	evs, err := s.store.GetEvidence(ctx, caseID, evidenceID)
	if err != nil || len(evs) == 0 {
		return domain.ErrEvidenceNotFound
	}

	// Delete from S3 (non-fatal)
	if s3Err := s.evidence.DeleteObject(ctx, evs[0].S3Key); s3Err != nil {
		log.Warn().Err(s3Err).Str("s3_key", evs[0].S3Key).Msg("S3 delete failed; removing DB record anyway")
	}

	if err := s.store.DeleteEvidence(ctx, caseID, evidenceID, deletedBy); err != nil {
		return err
	}
	s.auditAsync(ctx, caseID, deletedBy, "EVIDENCE_DELETED", fmt.Sprintf("evidence %s deleted", evidenceID))
	return nil
}

// ---------------------------------------------------------------------------
// SAR Generation
// ---------------------------------------------------------------------------

// GenerateSAR produces a SAR PDF, uploads it to S3, and records the action.
func (s *CaseService) GenerateSAR(ctx context.Context, caseID, generatedBy, notes string) (string, string, error) {
	c, actions, err := s.GetCase(ctx, caseID)
	if err != nil {
		return "", "", err
	}

	evs, _, err := s.GetEvidence(ctx, caseID, "")
	if err != nil {
		evs = nil // non-fatal
	}

	// Generate PDF bytes
	pdfBytes, err := s.sarGen.GenerateSAR(c, actions, evs)
	if err != nil {
		return "", "", fmt.Errorf("generate SAR PDF: %w", err)
	}

	// Upload to S3
	s3Key := s3store.SARKey(caseID)
	if err := s.evidence.PutObject(ctx, s3Key, "application/pdf", pdfBytes); err != nil {
		return "", "", fmt.Errorf("upload SAR to S3: %w", err)
	}

	// Persist S3 key and move status to PENDING_SAR
	updated, err := s.store.SetSAR(ctx, caseID, s3Key, generatedBy)
	if err != nil {
		return "", "", err
	}
	_ = updated

	// Pre-signed download URL
	downloadURL, err := s.evidence.PresignGetURL(ctx, s3Key)
	if err != nil {
		log.Warn().Err(err).Msg("failed to presign SAR download URL")
	}

	// Record on Fabric
	s.auditAsync(ctx, caseID, generatedBy, "SAR_GENERATED",
		fmt.Sprintf("SAR PDF uploaded to S3: %s. Notes: %s", s3Key, notes))

	log.Info().
		Str("case_id", caseID).
		Str("s3_key", s3Key).
		Str("generated_by", generatedBy).
		Msg("SAR generated and uploaded")

	return s3Key, downloadURL, nil
}

// ---------------------------------------------------------------------------
// Stats & workload
// ---------------------------------------------------------------------------

// GetCaseStats returns aggregate statistics for the given period.
func (s *CaseService) GetCaseStats(ctx context.Context, period string) (*domain.CaseStats, error) {
	return s.store.GetStats(ctx, period)
}

// GetInvestigatorWorkload returns workload counts per investigator.
func (s *CaseService) GetInvestigatorWorkload(ctx context.Context, ids []string) ([]*domain.InvestigatorWorkload, error) {
	return s.store.GetInvestigatorWorkload(ctx, ids)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// HealthCheck verifies all downstream dependencies.
func (s *CaseService) HealthCheck(ctx context.Context) map[string]string {
	status := map[string]string{
		"postgres":   "ok",
		"blockchain": "ok",
	}
	if err := s.store.Ping(ctx); err != nil {
		status["postgres"] = err.Error()
	}
	if s.blockchain != nil {
		if err := s.blockchain.Ping(ctx); err != nil {
			status["blockchain"] = err.Error()
		}
	}
	return status
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nextInvestigator returns the next investigator via round-robin.
func (s *CaseService) nextInvestigator() string {
	if len(s.investigators) == 0 {
		return ""
	}
	idx := s.rrIdx.Add(1) - 1
	return s.investigators[idx%uint64(len(s.investigators))]
}

// auditAsync records an investigator action on Hyperledger Fabric in a goroutine.
// Failures are logged but do not block the main operation.
func (s *CaseService) auditAsync(ctx context.Context, caseID, investigatorID, action, notes string) {
	if s.blockchain == nil {
		return
	}
	actionID := uuid.NewString()
	go func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		txID, err := s.blockchain.RecordInvestigatorAction(auditCtx, actionID, investigatorID, caseID, action, notes)
		if err != nil {
			log.Warn().Err(err).Str("case_id", caseID).Str("action", action).
				Msg("blockchain audit failed — continuing")
			return
		}
		// Best-effort: store tx_id on the case for reference
		if updateErr := s.store.UpdateCaseBlockchainTxID(context.Background(), caseID, txID); updateErr != nil {
			log.Warn().Err(updateErr).Str("case_id", caseID).Msg("failed to store blockchain tx_id")
		}
	}()
}
