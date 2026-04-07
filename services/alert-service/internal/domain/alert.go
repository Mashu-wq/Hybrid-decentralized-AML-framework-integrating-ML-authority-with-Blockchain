// Package domain contains the core business types for the Alert Service.
package domain

import (
	"errors"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Alert priority
// ---------------------------------------------------------------------------

// AlertPriority classifies urgency based on fraud_probability.
type AlertPriority int

const (
	PriorityUnspecified AlertPriority = 0
	PriorityLow         AlertPriority = 1 // fraud_prob < 0.5
	PriorityMedium      AlertPriority = 2 // 0.5–0.7
	PriorityHigh        AlertPriority = 3 // 0.7–0.85
	PriorityCritical    AlertPriority = 4 // > 0.85
)

// String returns the priority label.
func (p AlertPriority) String() string {
	switch p {
	case PriorityLow:
		return "LOW"
	case PriorityMedium:
		return "MEDIUM"
	case PriorityHigh:
		return "HIGH"
	case PriorityCritical:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// PriorityFromFraudProb maps a [0,1] fraud probability to an AlertPriority.
func PriorityFromFraudProb(prob float64) AlertPriority {
	switch {
	case prob > 0.85:
		return PriorityCritical
	case prob > 0.70:
		return PriorityHigh
	case prob >= 0.50:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

// ---------------------------------------------------------------------------
// Alert status lifecycle
// ---------------------------------------------------------------------------

// AlertStatus represents the lifecycle state of an alert.
type AlertStatus string

const (
	StatusOpen          AlertStatus = "OPEN"
	StatusInvestigating AlertStatus = "INVESTIGATING"
	StatusResolved      AlertStatus = "RESOLVED"
	StatusFalsePositive AlertStatus = "FALSE_POSITIVE"
	StatusEscalated     AlertStatus = "ESCALATED"
)

// ValidTransitions maps allowed status transitions.
var validTransitions = map[AlertStatus][]AlertStatus{
	StatusOpen:          {StatusInvestigating, StatusResolved, StatusFalsePositive, StatusEscalated},
	StatusInvestigating: {StatusResolved, StatusFalsePositive, StatusEscalated},
	StatusEscalated:     {StatusInvestigating, StatusResolved, StatusFalsePositive},
	StatusResolved:      {StatusOpen}, // re-open allowed
	StatusFalsePositive: {StatusOpen}, // re-open allowed
}

// ValidateTransition returns an error if moving from current to next is illegal.
func ValidateTransition(current, next AlertStatus) error {
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
// Kafka ingest event (from transactions.raw pipeline)
// ---------------------------------------------------------------------------

// AlertIngestEvent is the JSON message consumed from the alerts.created Kafka topic.
// Published by the Transaction Monitoring Service when fraud_probability > threshold.
type AlertIngestEvent struct {
	AlertID              string    `json:"alert_id"`
	CustomerID           string    `json:"customer_id"`
	TxHash               string    `json:"tx_hash"`
	FraudProbability     float64   `json:"fraud_probability"`
	RiskScore            float64   `json:"risk_score"`
	RiskLevel            string    `json:"risk_level"`
	ModelVersion         string    `json:"model_version"`
	SHAPExplanationJSON  string    `json:"shap_explanation_json,omitempty"`
	FeaturesSnapshotJSON string    `json:"features_snapshot_json,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// Validate checks required fields.
func (e *AlertIngestEvent) Validate() error {
	if e.AlertID == "" {
		return errors.New("alert_id is required")
	}
	if e.CustomerID == "" {
		return errors.New("customer_id is required")
	}
	if e.TxHash == "" {
		return errors.New("tx_hash is required")
	}
	if e.FraudProbability < 0 || e.FraudProbability > 1 {
		return fmt.Errorf("fraud_probability %f out of [0,1] range", e.FraudProbability)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Alert — persistent record in PostgreSQL
// ---------------------------------------------------------------------------

// Alert is the full alert record stored in PostgreSQL.
type Alert struct {
	AlertID              string        `db:"alert_id"`
	CustomerID           string        `db:"customer_id"`
	TxHash               string        `db:"tx_hash"`
	FraudProbability     float64       `db:"fraud_probability"`
	RiskScore            float64       `db:"risk_score"`
	Priority             AlertPriority `db:"priority"`
	Status               AlertStatus   `db:"status"`
	ModelVersion         string        `db:"model_version"`
	SHAPExplanationJSON  string        `db:"shap_explanation_json"`
	FeaturesSnapshotJSON string        `db:"features_snapshot_json"`
	AssigneeID           string        `db:"assignee_id"`
	AssignedAt           *time.Time    `db:"assigned_at"`
	EscalatedAt          *time.Time    `db:"escalated_at"`
	ResolvedAt           *time.Time    `db:"resolved_at"`
	ResolutionNotes      string        `db:"resolution_notes"`
	BlockchainTxID       string        `db:"blockchain_tx_id"`
	DedupHash            string        `db:"dedup_hash"`
	CreatedAt            time.Time     `db:"created_at"`
	UpdatedAt            time.Time     `db:"updated_at"`
}

// ---------------------------------------------------------------------------
// Alert filters (for list queries)
// ---------------------------------------------------------------------------

// AlertFilters holds query parameters for listing alerts.
type AlertFilters struct {
	Status       AlertStatus
	Priority     AlertPriority
	AssigneeID   string
	MinFraudProb float64
	StartTime    time.Time
	EndTime      time.Time
	SortBy       string // "created_at", "fraud_probability", "risk_score"
	Ascending    bool
	PageSize     int
	Offset       int
}

// AlertStats holds aggregate statistics about alerts.
type AlertStats struct {
	TotalAlerts          int
	OpenAlerts           int
	CriticalAlerts       int
	HighAlerts           int
	MediumAlerts         int
	LowAlerts            int
	ResolvedAlerts       int
	FalsePositives       int
	EscalatedAlerts      int
	AvgFraudProbability  float64
	FalsePositiveRate    float64
	AvgResolutionTimeMin float64
	EscalationRate       float64
	Period               string
}

// ---------------------------------------------------------------------------
// WebSocket broadcast message
// ---------------------------------------------------------------------------

// WSMessageType identifies the WebSocket event type.
type WSMessageType string

const (
	WSAlertCreated  WSMessageType = "ALERT_CREATED"
	WSAlertUpdated  WSMessageType = "ALERT_UPDATED"
	WSAlertEscalated WSMessageType = "ALERT_ESCALATED"
)

// WSMessage is the JSON payload broadcast to WebSocket clients.
type WSMessage struct {
	Type    WSMessageType `json:"type"`
	AlertID string        `json:"alert_id"`
	Data    *Alert        `json:"data"`
}

// ---------------------------------------------------------------------------
// Service errors
// ---------------------------------------------------------------------------

// AlertError wraps domain-level errors with a machine-readable code.
type AlertError struct {
	Code    string
	Message string
}

func (e *AlertError) Error() string { return e.Code + ": " + e.Message }

var (
	ErrAlertNotFound          = &AlertError{Code: "ALERT_NOT_FOUND", Message: "alert not found"}
	ErrDuplicateAlert         = &AlertError{Code: "DUPLICATE_ALERT", Message: "alert already exists (dedup)"}
	ErrInvalidTransition      = &AlertError{Code: "INVALID_TRANSITION", Message: "status transition not permitted"}
	ErrInvalidAlert           = &AlertError{Code: "INVALID_ALERT", Message: "alert validation failed"}
	ErrNotificationFailed     = &AlertError{Code: "NOTIFICATION_FAILED", Message: "one or more notifications failed"}
)
