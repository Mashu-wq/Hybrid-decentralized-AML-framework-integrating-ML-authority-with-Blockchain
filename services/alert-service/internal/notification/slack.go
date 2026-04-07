package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
)

// SlackSender posts alert notifications to a Slack incoming webhook.
type SlackSender struct {
	webhookURL string
	channel    string
	httpClient *http.Client
}

// NewSlackSender creates a new Slack webhook sender.
func NewSlackSender(webhookURL, channel string) *SlackSender {
	return &SlackSender{
		webhookURL: webhookURL,
		channel:    channel,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type slackPayload struct {
	Channel     string        `json:"channel,omitempty"`
	Text        string        `json:"text"`
	Attachments []slackAttach `json:"attachments,omitempty"`
}

type slackAttach struct {
	Color  string       `json:"color"`
	Title  string       `json:"title"`
	Fields []slackField `json:"fields"`
	Footer string       `json:"footer"`
	Ts     int64        `json:"ts"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// Send posts an alert to Slack. Returns the empty string as message ID (Slack
// incoming webhooks don't return an ID).
func (s *SlackSender) Send(ctx context.Context, a *domain.Alert, _ []string) (string, error) {
	color := slackColor(a.Priority)
	payload := slackPayload{
		Channel: s.channel,
		Text:    fmt.Sprintf(":rotating_light: *%s Fraud Alert* — %s", a.Priority.String(), a.AlertID),
		Attachments: []slackAttach{
			{
				Color: color,
				Title: fmt.Sprintf("Alert %s", a.AlertID),
				Fields: []slackField{
					{Title: "Customer", Value: a.CustomerID, Short: true},
					{Title: "TX Hash", Value: a.TxHash, Short: true},
					{Title: "Fraud Probability", Value: fmt.Sprintf("%.4f", a.FraudProbability), Short: true},
					{Title: "Risk Score", Value: fmt.Sprintf("%.2f", a.RiskScore), Short: true},
					{Title: "Status", Value: string(a.Status), Short: true},
					{Title: "Model", Value: a.ModelVersion, Short: true},
				},
				Footer: "AML Fraud Detection System",
				Ts:     a.CreatedAt.Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("slack http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("slack response %d", resp.StatusCode)
	}

	log.Info().Str("alert_id", a.AlertID).Str("channel", s.channel).Msg("Slack notification sent")
	return "", nil
}

func slackColor(p domain.AlertPriority) string {
	switch p {
	case domain.PriorityCritical:
		return "#FF0000"
	case domain.PriorityHigh:
		return "#FF8C00"
	case domain.PriorityMedium:
		return "#FFA500"
	default:
		return "#36A64F"
	}
}
