// Package domain contains the core business types for the Case Management Service.
package domain

import (
	"errors"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Case status lifecycle
// ---------------------------------------------------------------------------

// CaseStatus represents the workflow state of an investigation case.
type CaseStatus string

const (
	CaseStatusOpen        CaseStatus = "OPEN"
	CaseStatusInReview    CaseStatus = "IN_REVIEW"
	CaseStatusPendingSAR  CaseStatus = "PENDING_SAR"
	CaseStatusClosed      CaseStatus = "CLOSED"
	CaseStatusEscalated   CaseStatus = "ESCALATED"
)

// validTransitions maps allowed case status transitions.
var validTransitions = map[CaseStatus][]CaseStatus{
	CaseStatusOpen:       {CaseStatusInReview, CaseStatusClosed, CaseStatusEscalated},
	CaseStatusInReview:   {CaseStatusPendingSAR, CaseStatusClosed, CaseStatusEscalated},
	CaseStatusPendingSAR: {CaseStatusClosed, CaseStatusInReview},
	CaseStatusEscalated:  {CaseStatusInReview, CaseStatusClosed},
	CaseStatusClosed:     {CaseStatusOpen}, // re-open allowed
}

// ValidateTransition returns an error if moving from current to next is illegal.
func ValidateTransition(current, next CaseStatus) error {
	allowed, ok := validTransitions[current]
	if !ok {
		return fmt.Errorf("unknown current status: %s", current)
	}
	for _, s := range allowed {
		if s == next {
			return nil
		}
	}
	return fmt.Errorf("transition %s → %s is not permitted", current, next)
}

// ---------------------------------------------------------------------------
// Case priority
// ---------------------------------------------------------------------------

// CasePriority classifies urgency, derived from the originating alert priority.
type CasePriority int

const (
	CasePriorityUnspecified CasePriority = 0
	CasePriorityLow         CasePriority = 1
	CasePriorityMedium      CasePriority = 2
	CasePriorityHigh        CasePriority = 3
	CasePriorityCritical    CasePriority = 4
)

func (p CasePriority) String() string {
	switch p {
	case CasePriorityLow:
		return "LOW"
	case CasePriorityMedium:
		return "MEDIUM"
	case CasePriorityHigh:
		return "HIGH"
	case CasePriorityCritical:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// PriorityFromFraudProb maps fraud probability to case priority.
func PriorityFromFraudProb(prob float64) CasePriority {
	switch {
	case prob > 0.85:
		return CasePriorityCritical
	case prob > 0.70:
		return CasePriorityHigh
	case prob >= 0.50:
		return CasePriorityMedium
	default:
		return CasePriorityLow
	}
}

// ---------------------------------------------------------------------------
// Evidence type
// ---------------------------------------------------------------------------

// EvidenceType classifies the kind of evidence attached to a case.
type EvidenceType string

const (
	EvidenceTypeDocument      EvidenceType = "DOCUMENT"
	EvidenceTypeScreenshot    EvidenceType = "SCREENSHOT"
	EvidenceTypeTransaction   EvidenceType = "TRANSACTION"
	EvidenceTypeCommunication EvidenceType = "COMMUNICATION"
	EvidenceTypeOther         EvidenceType = "OTHER"
)

// ---------------------------------------------------------------------------
// Alert ingest event (consumed from alerts.created Kafka topic)
// ---------------------------------------------------------------------------

// AlertEvent is the Kafka message consumed from alerts.created.
// Used to auto-create cases for HIGH/CRITICAL alerts.
type AlertEvent struct {
	AlertID          string    `json:"alert_id"`
	CustomerID       string    `json:"customer_id"`
	TxHash           string    `json:"tx_hash"`
	FraudProbability float64   `json:"fraud_probability"`
	RiskScore        float64   `json:"risk_score"`
	Priority         string    `json:"risk_level"`
	ModelVersion     string    `json:"model_version"`
	CreatedAt        time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Core domain structs
// ---------------------------------------------------------------------------

// Case is the main investigation case record stored in PostgreSQL.
type Case struct {
	CaseID            string       `db:"case_id"`
	AlertID           string       `db:"alert_id"`
	CustomerID        string       `db:"customer_id"`
	TxHash            string       `db:"tx_hash"`
	Title             string       `db:"title"`
	Description       string       `db:"description"`
	Status            CaseStatus   `db:"status"`
	Priority          CasePriority `db:"priority"`
	AssigneeID        string       `db:"assignee_id"`
	AssignedAt        *time.Time   `db:"assigned_at"`
	FraudProbability  float64      `db:"fraud_probability"`
	RiskScore         float64      `db:"risk_score"`
	SARRequired       bool         `db:"sar_required"`
	SARS3Key          string       `db:"sar_s3_key"`
	SARGeneratedAt    *time.Time   `db:"sar_generated_at"`
	BlockchainTxID    string       `db:"blockchain_tx_id"`
	ResolutionSummary string       `db:"resolution_summary"`
	ClosedAt          *time.Time   `db:"closed_at"`
	CreatedAt         time.Time    `db:"created_at"`
	UpdatedAt         time.Time    `db:"updated_at"`
}

// Evidence represents a piece of evidence attached to a case.
type Evidence struct {
	EvidenceID   string       `db:"evidence_id"`
	CaseID       string       `db:"case_id"`
	UploadedBy   string       `db:"uploaded_by"`
	FileName     string       `db:"file_name"`
	FileSize     int64        `db:"file_size"`
	ContentType  string       `db:"content_type"`
	S3Key        string       `db:"s3_key"`
	EvidenceType EvidenceType `db:"evidence_type"`
	Notes        string       `db:"notes"`
	CreatedAt    time.Time    `db:"created_at"`
}

// CaseAction records every investigator action for immutable audit trail.
type CaseAction struct {
	ActionID       string    `db:"action_id"`
	CaseID         string    `db:"case_id"`
	InvestigatorID string    `db:"investigator_id"`
	Action         string    `db:"action"`
	Notes          string    `db:"notes"`
	BlockchainTxID string    `db:"blockchain_tx_id"`
	PerformedAt    time.Time `db:"performed_at"`
}

// CaseFilters holds query parameters for listing cases.
type CaseFilters struct {
	Status      CaseStatus
	Priority    CasePriority
	AssigneeID  string
	CustomerID  string
	SortBy      string
	Ascending   bool
	PageSize    int
	Offset      int
}

// CaseStats holds aggregate statistics for a reporting period.
type CaseStats struct {
	TotalCases         int
	OpenCases          int
	InReviewCases      int
	PendingSARCases    int
	ClosedCases        int
	CriticalCases      int
	SARGenerated       int
	AvgResolutionHours float64
	Period             string
}

// InvestigatorWorkload tracks how many active cases an investigator has.
type InvestigatorWorkload struct {
	InvestigatorID string
	ActiveCases    int
}

// ---------------------------------------------------------------------------
// Service errors
// ---------------------------------------------------------------------------

// CaseError wraps domain-level errors with a machine-readable code.
type CaseError struct {
	Code    string
	Message string
}

func (e *CaseError) Error() string { return e.Code + ": " + e.Message }

var (
	ErrCaseNotFound       = &CaseError{Code: "CASE_NOT_FOUND", Message: "case not found"}
	ErrEvidenceNotFound   = &CaseError{Code: "EVIDENCE_NOT_FOUND", Message: "evidence not found"}
	ErrDuplicateCase      = &CaseError{Code: "DUPLICATE_CASE", Message: "case already exists for this alert"}
	ErrInvalidTransition  = &CaseError{Code: "INVALID_TRANSITION", Message: "status transition not permitted"}
	ErrInvalidCase        = &CaseError{Code: "INVALID_CASE", Message: "case validation failed"}
	ErrSARAlreadyExists   = &CaseError{Code: "SAR_EXISTS", Message: "SAR already generated for this case"}
	ErrNoInvestigators    = &CaseError{Code: "NO_INVESTIGATORS", Message: "no investigators configured"}
)

// IsCaseError checks if the error is a CaseError with the given code.
func IsCaseError(err error, code string) bool {
	var ce *CaseError
	return errors.As(err, &ce) && ce.Code == code
}
