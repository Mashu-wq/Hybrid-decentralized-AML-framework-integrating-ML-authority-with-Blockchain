package notification

import (
	"context"
	"fmt"

	"github.com/fraud-detection/alert-service/internal/domain"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
	"github.com/rs/zerolog/log"
	"github.com/twilio/twilio-go"
)

// SMSSender sends alert notifications via Twilio SMS.
type SMSSender struct {
	client    *twilio.RestClient
	fromPhone string
	defaultTo []string
}

// NewSMSSender creates a new Twilio-backed SMS sender.
func NewSMSSender(accountSID, authToken, fromPhone string, defaultTo []string) *SMSSender {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})
	return &SMSSender{
		client:    client,
		fromPhone: fromPhone,
		defaultTo: defaultTo,
	}
}

// Send delivers an alert SMS. Only CRITICAL and HIGH alerts are typically SMS'd
// — callers are responsible for filtering by priority.
func (s *SMSSender) Send(_ context.Context, a *domain.Alert, recipients []string) (string, error) {
	to := recipients
	if len(to) == 0 {
		to = s.defaultTo
	}
	if len(to) == 0 {
		return "", fmt.Errorf("sms: no recipients configured")
	}

	body := fmt.Sprintf("[%s ALERT] Customer %s | Fraud prob %.2f | Alert ID: %s",
		a.Priority.String(), a.CustomerID, a.FraudProbability, a.AlertID)

	var lastSID string
	var lastErr error
	for _, phone := range to {
		params := &openapi.CreateMessageParams{}
		params.SetTo(phone)
		params.SetFrom(s.fromPhone)
		params.SetBody(body)

		resp, err := s.client.Api.CreateMessage(params)
		if err != nil {
			lastErr = fmt.Errorf("twilio send to %s: %w", phone, err)
			log.Warn().Err(lastErr).Str("alert_id", a.AlertID).Msg("SMS send failed")
			continue
		}
		if resp.Sid != nil {
			lastSID = *resp.Sid
		}
		log.Info().
			Str("alert_id", a.AlertID).
			Str("sid", lastSID).
			Str("to", phone).
			Msg("SMS notification sent")
	}

	if lastSID == "" && lastErr != nil {
		return "", lastErr
	}
	return lastSID, nil
}
