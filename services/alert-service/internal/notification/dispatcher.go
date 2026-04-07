package notification

import (
	"context"
	"fmt"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
)

// Sender is the common interface implemented by all notification providers.
type Sender interface {
	Send(ctx context.Context, a *domain.Alert, recipients []string) (msgID string, err error)
}

// NotificationResult holds the outcome of a single send attempt.
type NotificationResult struct {
	Channel   string
	Recipient string
	MsgID     string
	Err       error
}

// Dispatcher routes alert notifications to the appropriate channels based on priority.
type Dispatcher struct {
	email   *EmailSender
	sms     *SMSSender
	slack   *SlackSender
	webhook *WebhookSender

	// Repository for persisting notification logs.
	logger NotificationLogger
}

// NotificationLogger persists notification attempt records.
type NotificationLogger interface {
	LogNotification(ctx context.Context, alertID, channel, recipient string, success bool, msgID, errMsg string) error
}

// NewDispatcher creates a Dispatcher. Any sender may be nil (skipped).
func NewDispatcher(
	email *EmailSender,
	sms *SMSSender,
	slack *SlackSender,
	webhook *WebhookSender,
	logger NotificationLogger,
) *Dispatcher {
	return &Dispatcher{
		email:   email,
		sms:     sms,
		slack:   slack,
		webhook: webhook,
		logger:  logger,
	}
}

// Dispatch sends notifications for a newly created or escalated alert.
// Channels and priority rules:
//   - ALL priorities  → Slack (if configured)
//   - HIGH + CRITICAL → Email
//   - CRITICAL        → SMS
//   - ALL priorities  → Webhook (if configured)
//
// All channels are attempted even if one fails. Returns ErrNotificationFailed
// if at least one channel errors.
func (d *Dispatcher) Dispatch(ctx context.Context, a *domain.Alert) error {
	var results []NotificationResult

	// Slack — all priorities
	if d.slack != nil && d.slack.webhookURL != "" {
		results = append(results, d.sendOne(ctx, a, "SLACK", d.slack.channel, d.slack, nil))
	}

	// Email — HIGH and CRITICAL
	if d.email != nil && d.email.client != nil && a.Priority >= domain.PriorityHigh {
		results = append(results, d.sendOne(ctx, a, "EMAIL", d.email.fromEmail, d.email, nil))
	}

	// SMS — CRITICAL only
	if d.sms != nil && d.sms.client != nil && a.Priority == domain.PriorityCritical {
		results = append(results, d.sendOne(ctx, a, "SMS", d.sms.fromPhone, d.sms, nil))
	}

	// Webhook — all priorities
	if d.webhook != nil && len(d.webhook.urls) > 0 {
		for _, u := range d.webhook.urls {
			results = append(results, d.sendOne(ctx, a, "WEBHOOK", u, d.webhook, nil))
		}
	}

	// Persist all results
	var hasErr bool
	for _, r := range results {
		errMsg := ""
		if r.Err != nil {
			errMsg = r.Err.Error()
			hasErr = true
			log.Warn().Err(r.Err).
				Str("channel", r.Channel).
				Str("alert_id", a.AlertID).
				Msg("notification channel failed")
		}
		if d.logger != nil {
			_ = d.logger.LogNotification(ctx, a.AlertID, r.Channel, r.Recipient, r.Err == nil, r.MsgID, errMsg)
		}
	}

	if hasErr {
		return fmt.Errorf("%w: one or more channels failed for alert %s", domain.ErrNotificationFailed, a.AlertID)
	}
	return nil
}

func (d *Dispatcher) sendOne(ctx context.Context, a *domain.Alert, channel, recipient string, s Sender, recipients []string) NotificationResult {
	msgID, err := s.Send(ctx, a, recipients)
	return NotificationResult{
		Channel:   channel,
		Recipient: recipient,
		MsgID:     msgID,
		Err:       err,
	}
}
