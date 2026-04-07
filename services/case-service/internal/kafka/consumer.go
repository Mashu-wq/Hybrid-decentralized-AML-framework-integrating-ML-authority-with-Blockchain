// Package kafka implements the Kafka consumer for the Case Service.
// It subscribes to alerts.created and auto-creates investigation cases
// for HIGH (priority ≥ 3) and CRITICAL alerts.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

// CaseCreator is the function called for each qualifying alert event.
type CaseCreator func(ctx context.Context, event *domain.AlertEvent) error

// Consumer reads from the alerts.created Kafka topic and triggers case creation.
type Consumer struct {
	reader    *kafka.Reader
	processor CaseCreator
	workers   int
}

// NewConsumer constructs a Consumer.
func NewConsumer(brokers []string, topic, groupID string, workers, dialTimeoutSec int, processor CaseCreator) *Consumer {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       10 << 20,
		MaxWait:        time.Second,
		CommitInterval: 0,
		StartOffset:    kafka.FirstOffset,
		Dialer: &kafka.Dialer{
			Timeout:   time.Duration(dialTimeoutSec) * time.Second,
			DualStack: true,
		},
		ErrorLogger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			log.Error().Msgf("kafka reader: "+msg, args...)
		}),
	})
	return &Consumer{reader: r, processor: processor, workers: workers}
}

// Run starts the consumer loop and blocks until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	jobs := make(chan kafka.Message, c.workers*2)

	for i := 0; i < c.workers; i++ {
		go c.runWorker(ctx, jobs)
	}

	log.Info().
		Str("topic", c.reader.Config().Topic).
		Int("workers", c.workers).
		Msg("case-service Kafka consumer started")

	for {
		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Info().Msg("case-service Kafka consumer shutting down")
				break
			}
			log.Error().Err(err).Msg("kafka fetch error")
			continue
		}
		jobs <- msg
	}

	close(jobs)
	return c.reader.Close()
}

func (c *Consumer) runWorker(ctx context.Context, jobs <-chan kafka.Message) {
	for msg := range jobs {
		if err := c.processMessage(ctx, msg); err != nil {
			log.Warn().Err(err).
				Int64("offset", msg.Offset).
				Msg("case creation from alert failed — skipping")
			// DLQ: publish to alerts.created.dlq in production
		}
		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			log.Warn().Err(err).Msg("kafka commit failed")
		}
	}
}

func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message) error {
	var event domain.AlertEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		return fmt.Errorf("unmarshal alert event: %w", err)
	}

	// Only auto-create cases for HIGH and CRITICAL alerts
	priority := domain.PriorityFromFraudProb(event.FraudProbability)
	if priority < domain.CasePriorityHigh {
		log.Debug().
			Str("alert_id", event.AlertID).
			Float64("fraud_prob", event.FraudProbability).
			Msg("skipping case creation: below HIGH threshold")
		return nil
	}

	log.Debug().
		Str("alert_id", event.AlertID).
		Str("customer_id", event.CustomerID).
		Float64("fraud_prob", event.FraudProbability).
		Msg("auto-creating case from alert")

	return c.processor(ctx, &event)
}
