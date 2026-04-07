package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
)

// WebhookSender POSTs alert payloads to one or more configured URLs.
// Each request is signed with an HMAC-SHA256 header for the receiver to verify.
type WebhookSender struct {
	urls       []string
	secret     string
	httpClient *http.Client
}

// NewWebhookSender creates a WebhookSender for the given endpoint URLs.
func NewWebhookSender(urls []string, secret string) *WebhookSender {
	return &WebhookSender{
		urls:   urls,
		secret: secret,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type webhookPayload struct {
	Event     string       `json:"event"`
	Timestamp string       `json:"timestamp"`
	Alert     *domain.Alert `json:"alert"`
}

// Send POSTs the alert to all configured webhook URLs.
// All URLs are attempted even if some fail. Returns the first error if any.
func (s *WebhookSender) Send(ctx context.Context, a *domain.Alert, _ []string) (string, error) {
	if len(s.urls) == 0 {
		return "", nil
	}

	payload := webhookPayload{
		Event:     "FRAUD_ALERT",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Alert:     a,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("webhook marshal: %w", err)
	}

	sig := computeHMAC(body, s.secret)

	var firstErr error
	for _, url := range s.urls {
		if err := s.post(ctx, url, body, sig); err != nil {
			log.Warn().Err(err).Str("url", url).Str("alert_id", a.AlertID).Msg("webhook POST failed")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		log.Info().Str("url", url).Str("alert_id", a.AlertID).Msg("webhook notification sent")
	}
	return "", firstErr
}

func (s *WebhookSender) post(ctx context.Context, url string, body []byte, sig string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fraud-Signature", sig)
	req.Header.Set("X-Fraud-Timestamp", time.Now().UTC().Format(time.RFC3339))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func computeHMAC(payload []byte, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
