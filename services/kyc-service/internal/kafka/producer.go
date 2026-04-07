// Package kafka provides a Kafka event producer for the KYC service.
// KYC events are published to the kyc.events topic for downstream consumers
// (ML scoring service, alert engine, analytics pipeline).
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fraud-detection/kyc-service/internal/domain"
	"github.com/fraud-detection/shared/tracing"
	kafka "github.com/segmentio/kafka-go"
	"github.com/rs/zerolog"
)

// EventProducer publishes KYC domain events to a Kafka topic.
// CustomerID is used as the message key to guarantee partition ordering for
// all events belonging to the same customer.
type EventProducer struct {
	writer *kafka.Writer
	topic  string
	log    zerolog.Logger
}

// NewEventProducer creates a new EventProducer.
// brokers should list all Kafka broker addresses, e.g. ["localhost:9092"].
func NewEventProducer(brokers []string, topic string, log zerolog.Logger) *EventProducer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{}, // deterministic partition by key (customer ID)
		RequiredAcks: kafka.RequireOne,
		Async:        false, // synchronous writes for reliability
		BatchSize:    10,
		BatchTimeout: 10 * time.Millisecond,
		WriteTimeout: 10 * time.Second,
	}

	return &EventProducer{
		writer: writer,
		topic:  topic,
		log:    log.With().Str("component", "kafka_producer").Str("topic", topic).Logger(),
	}
}

// PublishKYCEvent serialises a KYCEvent to JSON and writes it to the Kafka topic.
// The message key is set to the CustomerID for ordered, per-customer partitioning.
// The current trace ID is injected into Kafka message headers for distributed tracing.
func (p *EventProducer) PublishKYCEvent(ctx context.Context, event *domain.KYCEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal KYC event: %w", err)
	}

	headers := []kafka.Header{
		{Key: "event_type", Value: []byte(event.EventType)},
		{Key: "content_type", Value: []byte("application/json")},
	}

	// Propagate trace context into Kafka headers for distributed tracing.
	if traceID := tracing.TraceID(ctx); traceID != "" {
		headers = append(headers, kafka.Header{Key: "x-trace-id", Value: []byte(traceID)})
	}
	if spanID := tracing.SpanID(ctx); spanID != "" {
		headers = append(headers, kafka.Header{Key: "x-span-id", Value: []byte(spanID)})
	}

	msg := kafka.Message{
		Key:     []byte(event.CustomerID), // partition key — ensures ordered delivery per customer
		Value:   payload,
		Headers: headers,
		Time:    event.Timestamp,
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.log.Error().
			Err(err).
			Str("customer_id", event.CustomerID).
			Str("event_type", event.EventType).
			Msg("failed to publish KYC event to Kafka")
		return fmt.Errorf("publish KYC event: %w", err)
	}

	p.log.Info().
		Str("customer_id", event.CustomerID).
		Str("event_type", event.EventType).
		Str("kyc_status", string(event.KYCStatus)).
		Msg("KYC event published")

	return nil
}

// Close flushes pending messages and closes the Kafka writer.
func (p *EventProducer) Close() error {
	if err := p.writer.Close(); err != nil {
		return fmt.Errorf("close kafka writer: %w", err)
	}
	return nil
}
