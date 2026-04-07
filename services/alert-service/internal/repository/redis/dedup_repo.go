// Package redis implements Redis-backed deduplication and caching for the Alert Service.
package redis

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	dedupTTL       = 24 * time.Hour
	dedupKeyPrefix = "alert:dedup:"
)

// DedupRepository uses Redis SET NX for idempotent alert deduplication.
// Key: alert:dedup:<sha256(customerID:txHash)>
// Value: alert_id (for audit logging)
// TTL:  24 hours — backed by the UNIQUE constraint in Postgres as a secondary guard.
type DedupRepository struct {
	client *redis.Client
}

// NewDedup creates a new DedupRepository.
func NewDedup(client *redis.Client) *DedupRepository {
	return &DedupRepository{client: client}
}

// Connect opens and validates a Redis connection.
func Connect(ctx context.Context, addr, password string, db int) (*redis.Client, error) {
	c := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return c, nil
}

// DedupHash computes the canonical deduplication hash for a (customerID, txHash) pair.
// This matches the SQL comment: SHA-256(customer_id || ':' || tx_hash).
func DedupHash(customerID, txHash string) string {
	h := sha256.Sum256([]byte(customerID + ":" + txHash))
	return fmt.Sprintf("%x", h)
}

// IsDuplicate returns true if this (customerID, txHash) pair has already been processed.
// It uses SET NX to atomically check-and-set in a single round-trip.
// Returns (isDup=false, hash, nil) when the key was newly set (first time seen).
// Returns (isDup=true,  hash, nil) when the key already exists.
func (r *DedupRepository) IsDuplicate(ctx context.Context, customerID, txHash, alertID string) (bool, string, error) {
	hash := DedupHash(customerID, txHash)
	key := dedupKeyPrefix + hash

	// SET key alertID NX EX 86400
	ok, err := r.client.SetNX(ctx, key, alertID, dedupTTL).Result()
	if err != nil {
		return false, hash, fmt.Errorf("redis setnx dedup: %w", err)
	}

	// ok=true  → key was newly set → NOT a duplicate
	// ok=false → key already existed → duplicate
	if !ok {
		existing, _ := r.client.Get(ctx, key).Result()
		log.Debug().
			Str("hash", hash).
			Str("existing_alert_id", existing).
			Str("new_alert_id", alertID).
			Msg("duplicate alert detected by Redis dedup")
		return true, hash, nil
	}

	return false, hash, nil
}

// Evict removes the dedup key — used when alert creation fails after the key was set,
// so a retry can succeed.
func (r *DedupRepository) Evict(ctx context.Context, hash string) {
	key := dedupKeyPrefix + hash
	if err := r.client.Del(ctx, key).Err(); err != nil {
		log.Warn().Err(err).Str("key", key).Msg("failed to evict dedup key on rollback")
	}
}

// Ping checks the Redis connection.
func (r *DedupRepository) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}
