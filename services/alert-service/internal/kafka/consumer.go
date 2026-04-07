// Package kafka implements the Kafka consumer for the Alert Service.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

// AlertProcessor is the function called for each valid ingest event.
type AlertProcessor func(ctx context.Context, event *domain.AlertIngestEvent) error

// Consumer reads from the alerts.created Kafka topic and dispatches to a worker pool.
type Consumer struct {
	reader    *kafka.Reader
	processor AlertProcessor
	workers   int
}

// NewConsumer constructs a Consumer connected to the given brokers.
func NewConsumer(brokers []string, topic, groupID string, workers, dialTimeoutSec int, processor AlertProcessor) *Consumer {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       10 << 20, // 10 MB
		MaxWait:        time.Second,
		CommitInterval: 0, // explicit commit after processing
		StartOffset:    kafka.FirstOffset,
		Dialer: &kafka.Dialer{
			Timeout:   time.Duration(dialTimeoutSec) * time.Second,
			DualStack: true,
		},
		ErrorLogger: kafka.LoggerFunc(func(msg string, args ...interface{}) {
			log.Error().Msgf("kafka reader: "+msg, args...)
		}),
	})

	return &Consumer{
		reader:    r,
		processor: processor,
		workers:   workers,
	}
}

// Run starts the consumer loop and blocks until ctx is cancelled.
// Messages are dispatched to a fixed-size worker pool via a buffered channel.
func (c *Consumer) Run(ctx context.Context) error {
	jobs := make(chan kafka.Message, c.workers*2)

	// Launch workers
	for i := 0; i < c.workers; i++ {
		go c.runWorker(ctx, jobs)
	}

	log.Info().
		Str("topic", c.reader.Config().Topic).
		Int("workers", c.workers).
		Msg("Kafka consumer started")

	for {
		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Info().Msg("Kafka consumer shutting down")
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
			log.Error().Err(err).
				Str("topic", msg.Topic).
				Int("partition", msg.Partition).
				Int64("offset", msg.Offset).
				Msg("message processing failed — skipping to avoid infinite retry")
			// DLQ: in production, publish to alerts.created.dlq here
		}
		// Commit even on processing error to advance offset
		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			log.Warn().Err(err).Msg("kafka commit failed")
		}
	}
}

func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message) error {
	var event domain.AlertIngestEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		return fmt.Errorf("unmarshal alert event (offset %d): %w", msg.Offset, err)
	}

	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid alert event (offset %d): %w", msg.Offset, err)
	}

	log.Debug().
		Str("alert_id", event.AlertID).
		Str("customer_id", event.CustomerID).
		Float64("fraud_prob", event.FraudProbability).
		Msg("processing alert ingest event")

	if err := c.processor(ctx, &event); err != nil {
		return fmt.Errorf("process alert %s: %w", event.AlertID, err)
	}
	return nil
}
