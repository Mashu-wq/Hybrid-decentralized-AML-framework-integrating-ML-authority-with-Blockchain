// Package notification contains multi-channel alert notification providers.
package notification

import (
	"context"
	"fmt"
	"strings"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// EmailSender sends alert notifications via SendGrid.
type EmailSender struct {
	client       *sendgrid.Client
	fromEmail    string
	fromName     string
	defaultTo    []string
}

// NewEmailSender creates a new SendGrid-backed email sender.
func NewEmailSender(apiKey, fromEmail, fromName string, defaultTo []string) *EmailSender {
	return &EmailSender{
		client:    sendgrid.NewSendClient(apiKey),
		fromEmail: fromEmail,
		fromName:  fromName,
		defaultTo: defaultTo,
	}
}

// Send delivers an alert notification email. If recipients is empty, the
// configured default recipients are used.
func (s *EmailSender) Send(ctx context.Context, a *domain.Alert, recipients []string) (string, error) {
	to := recipients
	if len(to) == 0 {
		to = s.defaultTo
	}
	if len(to) == 0 {
		return "", fmt.Errorf("email: no recipients configured")
	}

	from := mail.NewEmail(s.fromName, s.fromEmail)
	subject := fmt.Sprintf("[%s] Fraud Alert %s — %s",
		a.Priority.String(), a.AlertID, a.CustomerID)

	body := buildEmailBody(a)

	msg := mail.NewV3Mail()
	msg.SetFrom(from)
	msg.Subject = subject

	p := mail.NewPersonalization()
	for _, addr := range to {
		p.AddTos(mail.NewEmail("", strings.TrimSpace(addr)))
	}
	msg.AddPersonalizations(p)
	msg.AddContent(mail.NewContent("text/plain", body))

	resp, err := s.client.SendWithContext(ctx, msg)
	if err != nil {
		return "", fmt.Errorf("sendgrid send: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("sendgrid status %d: %s", resp.StatusCode, resp.Body)
	}

	msgID := resp.Headers.Get("X-Message-Id")
	log.Info().
		Str("alert_id", a.AlertID).
		Str("msg_id", msgID).
		Int("recipients", len(to)).
		Msg("email notification sent")

	return msgID, nil
}

func buildEmailBody(a *domain.Alert) string {
	return fmt.Sprintf(`Fraud Alert Notification
========================
Alert ID      : %s
Customer      : %s
TX Hash       : %s
Priority      : %s
Status        : %s
Fraud Prob    : %.4f
Risk Score    : %.2f
Model Version : %s
Created At    : %s

SHAP Explanation:
%s

This is an automated message from the AML Fraud Detection System.
`, a.AlertID, a.CustomerID, a.TxHash, a.Priority.String(),
		string(a.Status), a.FraudProbability, a.RiskScore,
		a.ModelVersion, a.CreatedAt.String(), a.SHAPExplanationJSON)
}
