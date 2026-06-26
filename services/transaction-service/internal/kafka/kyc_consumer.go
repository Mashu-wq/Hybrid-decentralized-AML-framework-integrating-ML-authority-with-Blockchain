package kafka

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

// ProfileCache caches a KYC customer profile for the feature pipeline to read
// off the hot path. Implemented by the Redis velocity repository.
type ProfileCache interface {
	SetCustomerProfile(ctx context.Context, profile *domain.CustomerProfile) error
}

// kycEvent mirrors the JSON the KYC service publishes to kyc.events. That
// service marshals its domain.KYCEvent without struct tags, so the JSON keys
// are the Go field names (PascalCase).
type kycEvent struct {
	EventType  string    `json:"EventType"`
	CustomerID string    `json:"CustomerID"`
	KYCStatus  string    `json:"KYCStatus"`
	RiskLevel  string    `json:"RiskLevel"`
	Timestamp  time.Time `json:"Timestamp"`
}

// KYCConsumer consumes kyc.events and maintains the customer profile cache so
// the transaction feature pipeline can read each customer's KYC risk level
// (which selects the FATF risk-based alert threshold) without a synchronous
// call to the KYC service.
type KYCConsumer struct {
	reader *kafka.Reader
	store  ProfileCache
	log    zerolog.Logger
}

// NewKYCConsumer creates a consumer subscribed to the kyc.events topic.
func NewKYCConsumer(
	brokers []string,
	topic, groupID string,
	dialTimeoutSec int,
	store ProfileCache,
	log zerolog.Logger,
) *KYCConsumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     groupID,
		MinBytes:    1,
		MaxBytes:    1 << 20, // 1 MB
		MaxWait:     time.Second,
		StartOffset: kafka.LastOffset,
		Dialer: &kafka.Dialer{
			Timeout:   time.Duration(dialTimeoutSec) * time.Second,
			DualStack: true,
		},
	})
	return &KYCConsumer{
		reader: reader,
		store:  store,
		log:    log.With().Str("component", "kyc_consumer").Str("topic", topic).Logger(),
	}
}

// Run consumes kyc.events until the context is cancelled.
func (c *KYCConsumer) Run(ctx context.Context) error {
	c.log.Info().Msg("KYC events consumer starting")
	for {
		m, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return c.reader.Close()
			}
			c.log.Error().Err(err).Msg("fetch kyc event")
			continue
		}
		c.handle(ctx, m.Value)
		if err := c.reader.CommitMessages(ctx, m); err != nil {
			c.log.Error().Err(err).Msg("commit kyc event offset")
		}
	}
}

func (c *KYCConsumer) handle(ctx context.Context, value []byte) {
	var ev kycEvent
	if err := json.Unmarshal(value, &ev); err != nil {
		c.log.Error().Err(err).Str("raw_value", string(value)).Msg("deserialise kyc event; skipping")
		return
	}
	if ev.CustomerID == "" {
		return
	}

	profile := &domain.CustomerProfile{
		CustomerID:   ev.CustomerID,
		RiskScore:    riskScoreForLevel(ev.RiskLevel),
		KYCRiskLevel: kycRiskLevelToInt(ev.RiskLevel),
		KYCDate:      ev.Timestamp,
	}
	if profile.KYCDate.IsZero() {
		profile.KYCDate = time.Now().UTC()
	}
	if err := c.store.SetCustomerProfile(ctx, profile); err != nil {
		c.log.Error().Err(err).Str("customer_id", ev.CustomerID).Msg("cache customer profile")
		return
	}
	c.log.Info().
		Str("customer_id", ev.CustomerID).
		Str("event_type", ev.EventType).
		Str("risk_level", ev.RiskLevel).
		Int("kyc_risk_level", profile.KYCRiskLevel).
		Msg("customer profile cached from KYC event")
}

// kycRiskLevelToInt maps the KYC service risk-level string to the integer scale
// used by the transaction feature pipeline (LOW=1 … CRITICAL=4). Unknown values
// default to medium, matching the feature extractor's safe default.
func kycRiskLevelToInt(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 2
	}
}

// riskScoreForLevel derives a representative 0–100 customer risk score from the
// KYC risk level, used as a feature when no finer score is available.
func riskScoreForLevel(level string) float64 {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "LOW":
		return 20
	case "MEDIUM":
		return 50
	case "HIGH":
		return 80
	case "CRITICAL":
		return 95
	default:
		return 50
	}
}
