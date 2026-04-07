// Package kafka (producer.go) publishes AlertEvent messages to the "alerts.created"
// Kafka topic. The Alert Service (Phase 9) subscribes to this topic to create
// alert records and send multi-channel notifications.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/fraud-detection/shared/tracing"
	kafka "github.com/segmentio/kafka-go"
	"github.com/rs/zerolog"
)

// AlertProducer publishes AlertEvent messages to the alerts.created Kafka topic.
// CustomerID is used as the partition key to guarantee ordered delivery per customer.
type AlertProducer struct {
	writer *kafka.Writer
	topic  string
	log    zerolog.Logger
}

// NewAlertProducer creates a new AlertProducer.
func NewAlertProducer(brokers []string, topic string, log zerolog.Logger) *AlertProducer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{}, // hash by customer_id for ordered per-customer delivery
		RequiredAcks: kafka.RequireOne,
		Async:        false, // synchronous — ensure the alert is durably recorded
		BatchSize:    1,     // alerts are critical-path; don't batch
		WriteTimeout: 10 * time.Second,
	}

	return &AlertProducer{
		writer: writer,
		topic:  topic,
		log:    log.With().Str("component", "alert_producer").Str("topic", topic).Logger(),
	}
}

// PublishAlert serialises an AlertEvent and writes it to the alerts.created topic.
// The message key is set to CustomerID for partition-ordered delivery.
func (p *AlertProducer) PublishAlert(ctx context.Context, alert *domain.AlertEvent) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert event: %w", err)
	}

	headers := []kafka.Header{
		{Key: "event_type", Value: []byte("FRAUD_ALERT")},
		{Key: "content_type", Value: []byte("application/json")},
		{Key: "risk_level", Value: []byte(alert.RiskLevel)},
	}

	// Propagate distributed trace context
	if traceID := tracing.TraceID(ctx); traceID != "" {
		headers = append(headers, kafka.Header{Key: "x-trace-id", Value: []byte(traceID)})
	}
	if spanID := tracing.SpanID(ctx); spanID != "" {
		headers = append(headers, kafka.Header{Key: "x-span-id", Value: []byte(spanID)})
	}

	msg := kafka.Message{
		Key:     []byte(alert.CustomerID), // partition key for ordered per-customer alerts
		Value:   payload,
		Headers: headers,
		Time:    alert.CreatedAt,
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.log.Error().
			Err(err).
			Str("alert_id", alert.AlertID).
			Str("customer_id", alert.CustomerID).
			Str("tx_hash", alert.TxHash).
			Float64("fraud_prob", alert.FraudProbability).
			Msg("failed to publish alert to Kafka")
		return fmt.Errorf("publish alert event: %w", err)
	}

	p.log.Info().
		Str("alert_id", alert.AlertID).
		Str("customer_id", alert.CustomerID).
		Str("tx_hash", alert.TxHash).
		Str("risk_level", alert.RiskLevel).
		Float64("fraud_prob", alert.FraudProbability).
		Msg("alert event published")

	return nil
}

// Close flushes pending messages and closes the Kafka writer.
func (p *AlertProducer) Close() error {
	if err := p.writer.Close(); err != nil {
		return fmt.Errorf("close alert producer: %w", err)
	}
	return nil
}
