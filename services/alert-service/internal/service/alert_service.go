// Package service contains the core Alert Service business logic.
package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/fraud-detection/alert-service/internal/notification"
	"github.com/rs/zerolog/log"
)

// ---------------------------------------------------------------------------
// Port interfaces (dependency inversion)
// ---------------------------------------------------------------------------

// AlertStore persists and retrieves alerts from PostgreSQL.
type AlertStore interface {
	Create(ctx context.Context, a *domain.Alert) error
	GetByID(ctx context.Context, alertID string) (*domain.Alert, error)
	List(ctx context.Context, f domain.AlertFilters) ([]*domain.Alert, int, error)
	GetByCustomer(ctx context.Context, customerID string, limit, offset int) ([]*domain.Alert, error)
	UpdateStatus(ctx context.Context, alertID, changedBy, notes string, newStatus domain.AlertStatus) (*domain.Alert, error)
	Assign(ctx context.Context, alertID, assigneeID string) (*domain.Alert, error)
	GetEscalationCandidates(ctx context.Context, threshold time.Duration) ([]*domain.Alert, error)
	GetStats(ctx context.Context, period string) (*domain.AlertStats, error)
	LogNotification(ctx context.Context, alertID, channel, recipient string, success bool, msgID, errMsg string) error
	Ping(ctx context.Context) error
}

// DedupStore checks and marks processed alert dedup hashes in Redis.
type DedupStore interface {
	IsDuplicate(ctx context.Context, customerID, txHash, alertID string) (bool, string, error)
	Evict(ctx context.Context, hash string)
	Ping(ctx context.Context) error
}

// Broadcaster sends real-time WSMessages to connected dashboard clients.
type Broadcaster interface {
	BroadcastAlert(msg *domain.WSMessage)
}

// ---------------------------------------------------------------------------
// AlertService
// ---------------------------------------------------------------------------

// AlertService orchestrates alert lifecycle, notifications, and broadcasts.
type AlertService struct {
	store      AlertStore
	dedup      DedupStore
	dispatcher *notification.Dispatcher
	hub        Broadcaster
}

// New creates an AlertService with all required dependencies.
func New(
	store AlertStore,
	dedup DedupStore,
	dispatcher *notification.Dispatcher,
	hub Broadcaster,
) *AlertService {
	return &AlertService{
		store:      store,
		dedup:      dedup,
		dispatcher: dispatcher,
		hub:        hub,
	}
}

// ---------------------------------------------------------------------------
// Ingest (Kafka consumer entry point)
// ---------------------------------------------------------------------------

// IngestAlert processes an AlertIngestEvent from the alerts.created Kafka topic.
//
// Steps:
//  1. Validate the event
//  2. Dedup check via Redis (fast path) — Postgres UNIQUE constraint is the safety net
//  3. Persist in PostgreSQL
//  4. Send multi-channel notifications (non-fatal if they fail)
//  5. Broadcast to WebSocket clients
func (s *AlertService) IngestAlert(ctx context.Context, event *domain.AlertIngestEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrInvalidAlert, err)
	}

	// --- dedup ---
	isDup, dedupHash, err := s.dedup.IsDuplicate(ctx, event.CustomerID, event.TxHash, event.AlertID)
	if err != nil {
		log.Warn().Err(err).Str("alert_id", event.AlertID).Msg("dedup check failed — proceeding (Postgres UNIQUE will guard)")
		dedupHash = computeHash(event.CustomerID, event.TxHash)
	}
	if isDup {
		log.Info().Str("alert_id", event.AlertID).Msg("duplicate alert discarded")
		return nil
	}

	priority := domain.PriorityFromFraudProb(event.FraudProbability)
	now := time.Now().UTC()

	alert := &domain.Alert{
		AlertID:              event.AlertID,
		CustomerID:           event.CustomerID,
		TxHash:               event.TxHash,
		FraudProbability:     event.FraudProbability,
		RiskScore:            event.RiskScore,
		Priority:             priority,
		Status:               domain.StatusOpen,
		ModelVersion:         event.ModelVersion,
		SHAPExplanationJSON:  orDefault(event.SHAPExplanationJSON, "[]"),
		FeaturesSnapshotJSON: orDefault(event.FeaturesSnapshotJSON, "{}"),
		DedupHash:            dedupHash,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.store.Create(ctx, alert); err != nil {
		// Postgres UNIQUE violation means another worker already persisted it
		if err == domain.ErrDuplicateAlert {
			s.dedup.Evict(ctx, dedupHash) // let Redis catch next time
			log.Info().Str("alert_id", event.AlertID).Msg("duplicate alert (Postgres constraint)")
			return nil
		}
		s.dedup.Evict(ctx, dedupHash) // rollback Redis key so retry can succeed
		return fmt.Errorf("persist alert: %w", err)
	}

	log.Info().
		Str("alert_id", alert.AlertID).
		Str("customer_id", alert.CustomerID).
		Str("priority", priority.String()).
		Float64("fraud_prob", event.FraudProbability).
		Msg("alert created")

	// --- notifications (non-fatal) ---
	if s.dispatcher != nil {
		if notifErr := s.dispatcher.Dispatch(ctx, alert); notifErr != nil {
			log.Warn().Err(notifErr).Str("alert_id", alert.AlertID).Msg("notification partially failed")
		}
	}

	// --- real-time broadcast ---
	if s.hub != nil {
		s.hub.BroadcastAlert(&domain.WSMessage{
			Type:    domain.WSAlertCreated,
			AlertID: alert.AlertID,
			Data:    alert,
		})
	}

	return nil
}

// ---------------------------------------------------------------------------
// Lifecycle mutations
// ---------------------------------------------------------------------------

// GetAlert retrieves a single alert by ID.
func (s *AlertService) GetAlert(ctx context.Context, alertID string) (*domain.Alert, error) {
	return s.store.GetByID(ctx, alertID)
}

// ListAlerts returns a filtered, paginated list of alerts and the total count.
func (s *AlertService) ListAlerts(ctx context.Context, f domain.AlertFilters) ([]*domain.Alert, int, error) {
	return s.store.List(ctx, f)
}

// GetAlertsByCustomer returns alert history for a customer.
func (s *AlertService) GetAlertsByCustomer(ctx context.Context, customerID string, limit, offset int) ([]*domain.Alert, error) {
	return s.store.GetByCustomer(ctx, customerID, limit, offset)
}

// UpdateStatus transitions an alert to a new status.
func (s *AlertService) UpdateStatus(ctx context.Context, alertID, changedBy, notes string, newStatus domain.AlertStatus) (*domain.Alert, error) {
	updated, err := s.store.UpdateStatus(ctx, alertID, changedBy, notes, newStatus)
	if err != nil {
		return nil, err
	}

	if s.hub != nil {
		s.hub.BroadcastAlert(&domain.WSMessage{
			Type:    domain.WSAlertUpdated,
			AlertID: updated.AlertID,
			Data:    updated,
		})
	}
	return updated, nil
}

// AssignAlert assigns an alert to an analyst.
func (s *AlertService) AssignAlert(ctx context.Context, alertID, assigneeID string) (*domain.Alert, error) {
	updated, err := s.store.Assign(ctx, alertID, assigneeID)
	if err != nil {
		return nil, err
	}
	if s.hub != nil {
		s.hub.BroadcastAlert(&domain.WSMessage{
			Type:    domain.WSAlertUpdated,
			AlertID: updated.AlertID,
			Data:    updated,
		})
	}
	return updated, nil
}

// EscalateAlert transitions an alert to ESCALATED and assigns a senior analyst.
// Implements the escalation.AlertEscalator interface.
func (s *AlertService) EscalateAlert(ctx context.Context, alertID, analystID, reason string) (*domain.Alert, error) {
	updated, err := s.store.UpdateStatus(ctx, alertID, "system", reason, domain.StatusEscalated)
	if err != nil {
		return nil, err
	}

	// Assign the senior analyst
	if analystID != "" && analystID != "system" {
		updated, err = s.store.Assign(ctx, alertID, analystID)
		if err != nil {
			log.Warn().Err(err).Str("alert_id", alertID).Msg("escalation: assign failed after status update")
		}
	}

	if s.hub != nil {
		s.hub.BroadcastAlert(&domain.WSMessage{
			Type:    domain.WSAlertEscalated,
			AlertID: updated.AlertID,
			Data:    updated,
		})
	}

	// Send notifications for escalated alert
	if s.dispatcher != nil {
		if notifErr := s.dispatcher.Dispatch(ctx, updated); notifErr != nil {
			log.Warn().Err(notifErr).Str("alert_id", alertID).Msg("escalation notification partially failed")
		}
	}

	return updated, nil
}

// GetEscalationCandidates returns alerts eligible for auto-escalation.
// Implements the escalation.AlertEscalator interface.
func (s *AlertService) GetEscalationCandidates(ctx context.Context, threshold time.Duration) ([]*domain.Alert, error) {
	return s.store.GetEscalationCandidates(ctx, threshold)
}

// GetStats returns aggregate statistics for the given period ("24h", "7d", "30d").
func (s *AlertService) GetStats(ctx context.Context, period string) (*domain.AlertStats, error) {
	return s.store.GetStats(ctx, period)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// HealthCheck verifies all downstream dependencies.
func (s *AlertService) HealthCheck(ctx context.Context) map[string]string {
	status := map[string]string{
		"postgres": "ok",
		"redis":    "ok",
	}
	if err := s.store.Ping(ctx); err != nil {
		status["postgres"] = err.Error()
	}
	if err := s.dedup.Ping(ctx); err != nil {
		status["redis"] = err.Error()
	}
	return status
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func computeHash(customerID, txHash string) string {
	h := sha256.Sum256([]byte(customerID + ":" + txHash))
	return fmt.Sprintf("%x", h)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
