// Package redis implements the Redis-backed token cache for the IAM service.
// Stores: access token JTI blocklist (for fast revocation checks),
// MFA challenge state, and rate-limit counters.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenRepo wraps a Redis client for token-related operations.
type TokenRepo struct {
	client *redis.Client
}

// NewTokenRepo creates a new TokenRepo.
func NewTokenRepo(client *redis.Client) *TokenRepo {
	return &TokenRepo{client: client}
}

// Key prefixes — keep consistent to avoid collisions.
const (
	prefixJTIBlocklist  = "iam:jti:blocked:"   // iam:jti:blocked:<jti>
	prefixMFAChallenge  = "iam:mfa:challenge:"  // iam:mfa:challenge:<challenge_id>
	prefixRateLogin     = "iam:rate:login:"     // iam:rate:login:<email>
	prefixActiveSessions = "iam:sessions:"      // iam:sessions:<user_id>  (set of JTIs)
)

// --- JTI Blocklist (access token revocation) ---

// BlockJTI adds a JWT ID to the blocklist with an expiry matching the token TTL.
// ValidateToken checks this before accepting a token — O(1) lookup.
func (r *TokenRepo) BlockJTI(ctx context.Context, jti string, ttl time.Duration) error {
	key := prefixJTIBlocklist + jti
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsJTIBlocked returns true if the JTI is in the blocklist.
func (r *TokenRepo) IsJTIBlocked(ctx context.Context, jti string) (bool, error) {
	key := prefixJTIBlocklist + jti
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("check jti blocklist: %w", err)
	}
	return result > 0, nil
}

// --- Active session tracking ---

// TrackSession adds a JTI to the user's set of active sessions.
func (r *TokenRepo) TrackSession(ctx context.Context, userID, jti string, ttl time.Duration) error {
	key := prefixActiveSessions + userID
	pipe := r.client.Pipeline()
	pipe.SAdd(ctx, key, jti)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// RevokeAllSessions blocklists all tracked JTIs for a user (logout all devices).
// TTL is applied per JTI to match the original access token TTL.
func (r *TokenRepo) RevokeAllSessions(ctx context.Context, userID string, jtiTTL time.Duration) error {
	key := prefixActiveSessions + userID
	jtis, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("get active sessions: %w", err)
	}

	if len(jtis) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	for _, jti := range jtis {
		pipe.Set(ctx, prefixJTIBlocklist+jti, "1", jtiTTL)
	}
	pipe.Del(ctx, key)
	_, err = pipe.Exec(ctx)
	return err
}

// --- MFA Challenge state ---

// MFAChallenge holds temporary state for a pending MFA verification.
type MFAChallenge struct {
	UserID    string
	Email     string
	DeviceID  string
	IPAddress string
	UserAgent string
}

// StoreMFAChallenge persists a challenge for a short window (5 minutes).
// The challenge_id is returned to the client in LoginResponse.mfa_challenge_id.
func (r *TokenRepo) StoreMFAChallenge(ctx context.Context, challengeID string, c MFAChallenge) error {
	key := prefixMFAChallenge + challengeID
	// Store as Redis hash for structured access
	return r.client.HSet(ctx, key,
		"user_id", c.UserID,
		"email", c.Email,
		"device_id", c.DeviceID,
		"ip_address", c.IPAddress,
		"user_agent", c.UserAgent,
	).Err() // TTL set separately
}

// SetMFAChallengeTTL sets the expiry on a challenge key.
func (r *TokenRepo) SetMFAChallengeTTL(ctx context.Context, challengeID string, ttl time.Duration) error {
	return r.client.Expire(ctx, prefixMFAChallenge+challengeID, ttl).Err()
}

// GetMFAChallenge retrieves and deletes the MFA challenge (single-use).
func (r *TokenRepo) GetMFAChallenge(ctx context.Context, challengeID string) (*MFAChallenge, error) {
	key := prefixMFAChallenge + challengeID

	fields, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("get mfa challenge: %w", err)
	}
	if len(fields) == 0 {
		return nil, nil // challenge not found or expired
	}

	// Delete after retrieval (single-use)
	r.client.Del(ctx, key) //nolint:errcheck

	return &MFAChallenge{
		UserID:    fields["user_id"],
		Email:     fields["email"],
		DeviceID:  fields["device_id"],
		IPAddress: fields["ip_address"],
		UserAgent: fields["user_agent"],
	}, nil
}

// --- Rate limiting ---

// LoginAttemptResult holds the result of a rate-limit increment.
type LoginAttemptResult struct {
	Count    int64
	TTL      time.Duration
	IsLocked bool
}

// RecordLoginAttempt increments the login attempt counter for an email.
// The counter expires after windowDuration. Returns the current count.
func (r *TokenRepo) RecordLoginAttempt(ctx context.Context, email string, windowDuration time.Duration) (int64, error) {
	key := prefixRateLogin + email

	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, windowDuration) // only sets TTL if not already set (NX behaviour)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("record login attempt: %w", err)
	}
	return incrCmd.Val(), nil
}

// ResetLoginAttempts removes the rate-limit counter for an email (called on success).
func (r *TokenRepo) ResetLoginAttempts(ctx context.Context, email string) error {
	return r.client.Del(ctx, prefixRateLogin+email).Err()
}

// GetLoginAttemptCount returns the current failed attempt count for an email.
func (r *TokenRepo) GetLoginAttemptCount(ctx context.Context, email string) (int64, error) {
	count, err := r.client.Get(ctx, prefixRateLogin+email).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// --- Health ---

// Ping verifies the Redis connection is alive.
func (r *TokenRepo) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}
