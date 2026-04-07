// Package kafka provides Kafka consumer and producer implementations for the
// Transaction Monitoring Service.
//
// The consumer reads from the "transactions.raw" topic and dispatches each
// message to the transaction processing pipeline via a configurable worker pool.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	kafka "github.com/segmentio/kafka-go"
	"github.com/rs/zerolog"
)

// MessageProcessor defines the processing function called for each raw transaction.
// Implementations must be safe for concurrent use from multiple goroutines.
type MessageProcessor func(ctx context.Context, raw *domain.RawTransaction) error

// Consumer reads raw transactions from a Kafka topic and dispatches them to
// a pool of workers for parallel processing.
type Consumer struct {
	reader    *kafka.Reader
	processor MessageProcessor
	workers   int
	log       zerolog.Logger
}

// NewConsumer creates a new Consumer subscribed to the given Kafka topic.
//
//   - brokers: list of Kafka broker addresses, e.g. ["localhost:9092"]
//   - topic:   topic name to consume, typically "transactions.raw"
//   - groupID: consumer group identifier for offset tracking
//   - workers: number of parallel processing goroutines
//   - dialTimeout: connection timeout in seconds
func NewConsumer(
	brokers []string,
	topic, groupID string,
	workers, dialTimeoutSec int,
	processor MessageProcessor,
	log zerolog.Logger,
) *Consumer {
	readerCfg := kafka.ReaderConfig{
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     groupID,
		MinBytes:    1,           // return messages immediately
		MaxBytes:    10 << 20,   // 10 MB max per fetch
		MaxWait:     time.Second, // max latency if < MinBytes are available
		StartOffset: kafka.LastOffset,
		// Commit offsets only after successful processing
		CommitInterval: 0,
		Dialer: &kafka.Dialer{
			Timeout:   time.Duration(dialTimeoutSec) * time.Second,
			DualStack: true,
		},
	}

	reader := kafka.NewReader(readerCfg)

	return &Consumer{
		reader:    reader,
		processor: processor,
		workers:   workers,
		log:       log.With().Str("component", "kafka_consumer").Str("topic", topic).Logger(),
	}
}

// Run starts the consumer loop and blocks until ctx is cancelled.
// Messages are dispatched to a worker pool of size c.workers.
// Each worker commits its message offset after successful processing.
// Failed messages are logged and their offsets are NOT committed, causing
// them to be re-delivered after the session timeout.
func (c *Consumer) Run(ctx context.Context) error {
	c.log.Info().Int("workers", c.workers).Msg("starting Kafka consumer")

	// Buffered channel acts as the work queue between the reader and workers.
	jobs := make(chan kafka.Message, c.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < c.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			c.runWorker(ctx, workerID, jobs)
		}(i)
	}

	// Reader loop — fetch messages and dispatch to workers.
	for {
		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Normal shutdown
				c.log.Info().Msg("context cancelled — stopping reader")
				close(jobs)
				wg.Wait()
				return c.reader.Close()
			}
			c.log.Error().Err(err).Msg("Kafka FetchMessage error; retrying in 1s")
			// Brief back-off before retrying to avoid tight error loops.
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return c.reader.Close()
			case <-time.After(time.Second):
				continue
			}
		}

		select {
		case jobs <- msg:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return c.reader.Close()
		}
	}
}

// runWorker processes messages from the jobs channel until it is closed.
func (c *Consumer) runWorker(ctx context.Context, id int, jobs <-chan kafka.Message) {
	log := c.log.With().Int("worker_id", id).Logger()
	for msg := range jobs {
		c.processMessage(ctx, log, msg)
	}
}

// processMessage deserialises one Kafka message and calls the processor.
func (c *Consumer) processMessage(ctx context.Context, log zerolog.Logger, msg kafka.Message) {
	start := time.Now()

	// Extract trace ID from headers for distributed tracing.
	traceID := headerValue(msg.Headers, "x-trace-id")
	log = log.With().
		Int64("offset", msg.Offset).
		Int("partition", msg.Partition).
		Str("key", string(msg.Key)).
		Str("trace_id", traceID).
		Logger()

	var raw domain.RawTransaction
	if err := json.Unmarshal(msg.Value, &raw); err != nil {
		log.Error().
			Err(err).
			Str("raw_value", truncate(string(msg.Value), 200)).
			Msg("failed to deserialise transaction message; skipping (DLQ TODO)")
		// TODO: Publish to dead-letter queue instead of silently dropping.
		// Commit offset so we don't block the partition on a permanently bad message.
		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			log.Warn().Err(err).Msg("failed to commit DLQ offset")
		}
		return
	}

	if err := raw.Validate(); err != nil {
		log.Warn().Err(err).Str("tx_hash", raw.TxHash).Msg("invalid transaction; skipping")
		_ = c.reader.CommitMessages(ctx, msg)
		return
	}

	if err := c.processor(ctx, &raw); err != nil {
		log.Error().
			Err(err).
			Str("tx_hash", raw.TxHash).
			Dur("elapsed", time.Since(start)).
			Msg("transaction processing failed; not committing offset (will retry)")
		return
	}

	if err := c.reader.CommitMessages(ctx, msg); err != nil {
		log.Warn().Err(err).Str("tx_hash", raw.TxHash).Msg("failed to commit offset")
	}

	log.Info().
		Str("tx_hash", raw.TxHash).
		Str("customer_id", raw.CustomerID).
		Dur("elapsed", time.Since(start)).
		Msg("transaction processed and committed")
}

// Close shuts down the consumer reader.
func (c *Consumer) Close() error {
	if err := c.reader.Close(); err != nil {
		return fmt.Errorf("close kafka reader: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func headerValue(headers []kafka.Header, key string) string {
	for _, h := range headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
