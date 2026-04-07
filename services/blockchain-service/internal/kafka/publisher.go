package kafka

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	kafkago "github.com/segmentio/kafka-go"
)

type Publisher interface {
	Publish(ctx context.Context, key string, value []byte) error
	Close() error
}

type writerPublisher struct {
	writer *kafkago.Writer
}

type noopPublisher struct {
	log zerolog.Logger
}

func NewPublisher(brokers []string, topic string, log zerolog.Logger) Publisher {
	if len(brokers) == 0 || topic == "" {
		return &noopPublisher{log: log.With().Str("component", "kafka_publisher").Logger()}
	}

	return &writerPublisher{
		writer: &kafkago.Writer{
			Addr:         kafkago.TCP(brokers...),
			Topic:        topic,
			Balancer:     &kafkago.LeastBytes{},
			RequiredAcks: kafkago.RequireOne,
			Async:        false,
			WriteTimeout: 10 * time.Second,
			ReadTimeout:  10 * time.Second,
		},
	}
}

func (p *writerPublisher) Publish(ctx context.Context, key string, value []byte) error {
	return p.writer.WriteMessages(ctx, kafkago.Message{Key: []byte(key), Value: value})
}

func (p *writerPublisher) Close() error {
	return p.writer.Close()
}

func (p *noopPublisher) Publish(ctx context.Context, key string, value []byte) error {
	p.log.Debug().Str("key", key).Msg("skipping kafka publish because no brokers are configured")
	return nil
}

func (p *noopPublisher) Close() error {
	return nil
}
