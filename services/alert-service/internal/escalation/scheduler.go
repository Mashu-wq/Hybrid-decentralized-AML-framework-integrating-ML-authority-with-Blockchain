// Package escalation implements the automatic CRITICAL/HIGH alert escalation scheduler.
package escalation

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
)

// AlertEscalator is the minimum interface the scheduler needs from the alert service.
type AlertEscalator interface {
	EscalateAlert(ctx context.Context, alertID, analystID, reason string) (*domain.Alert, error)
	GetEscalationCandidates(ctx context.Context, threshold time.Duration) ([]*domain.Alert, error)
}

// Scheduler polls PostgreSQL on a fixed interval and escalates overdue alerts.
type Scheduler struct {
	service        AlertEscalator
	interval       time.Duration
	threshold      time.Duration
	seniorAnalysts []string
	roundRobinIdx  atomic.Uint64
	escalated      atomic.Int64 // lifetime counter for observability
}

// NewScheduler constructs a Scheduler.
func NewScheduler(
	service AlertEscalator,
	interval, threshold time.Duration,
	seniorAnalysts []string,
) *Scheduler {
	return &Scheduler{
		service:        service,
		interval:       interval,
		threshold:      threshold,
		seniorAnalysts: seniorAnalysts,
	}
}

// Run starts the escalation loop. Blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	log.Info().
		Dur("interval", s.interval).
		Dur("threshold", s.threshold).
		Int("analysts", len(s.seniorAnalysts)).
		Msg("escalation scheduler started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("escalation scheduler stopped")
			return
		case <-ticker.C:
			s.runCycle(ctx)
		}
	}
}

func (s *Scheduler) runCycle(ctx context.Context) {
	candidates, err := s.service.GetEscalationCandidates(ctx, s.threshold)
	if err != nil {
		log.Error().Err(err).Msg("escalation: failed to fetch candidates")
		return
	}
	if len(candidates) == 0 {
		return
	}

	log.Info().Int("candidates", len(candidates)).Msg("escalation: processing candidates")

	for _, a := range candidates {
		analystID := s.nextAnalyst()
		reason := "auto-escalated: unresolved CRITICAL/HIGH alert exceeded threshold"

		escalated, err := s.service.EscalateAlert(ctx, a.AlertID, analystID, reason)
		if err != nil {
			log.Warn().Err(err).
				Str("alert_id", a.AlertID).
				Str("analyst", analystID).
				Msg("escalation failed")
			continue
		}

		s.escalated.Add(1)
		log.Info().
			Str("alert_id", escalated.AlertID).
			Str("assigned_to", analystID).
			Str("priority", escalated.Priority.String()).
			Msg("alert auto-escalated")
	}
}

// nextAnalyst returns the next senior analyst via round-robin.
// Returns "system" if no analysts are configured.
func (s *Scheduler) nextAnalyst() string {
	if len(s.seniorAnalysts) == 0 {
		return "system"
	}
	idx := s.roundRobinIdx.Add(1) - 1
	return s.seniorAnalysts[idx%uint64(len(s.seniorAnalysts))]
}

// EscalatedCount returns the total number of auto-escalations since startup.
func (s *Scheduler) EscalatedCount() int64 {
	return s.escalated.Load()
}
