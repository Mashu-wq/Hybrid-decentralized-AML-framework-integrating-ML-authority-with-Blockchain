// Package redis — service adapter implementations.
//
// MFAChallengeAdapter wraps *TokenRepo to satisfy service.MFAChallengeStore.
// It is needed because the redis package defines its own MFAChallenge struct to
// avoid a circular import with the service package, yet the service interface
// uses service.MFAChallenge. The adapter translates between the two.
//
// RateLimiter methods (RecordLoginAttempt, ResetLoginAttempts,
// GetLoginAttemptCount) are implemented directly on *TokenRepo with exactly
// the signatures required by service.RateLimiter, so no adapter is needed
// there — *TokenRepo can be passed directly.
package redis

import (
	"context"
	"time"

	"github.com/fraud-detection/iam-service/internal/service"
)

// MFAChallengeAdapter wraps *TokenRepo and translates between redis.MFAChallenge
// and service.MFAChallenge so that *TokenRepo can satisfy service.MFAChallengeStore.
type MFAChallengeAdapter struct {
	repo *TokenRepo
}

// NewMFAChallengeAdapter returns an adapter that satisfies service.MFAChallengeStore.
func NewMFAChallengeAdapter(repo *TokenRepo) *MFAChallengeAdapter {
	return &MFAChallengeAdapter{repo: repo}
}

// Compile-time interface assertion.
var _ service.MFAChallengeStore = (*MFAChallengeAdapter)(nil)

// StoreMFAChallenge converts a service.MFAChallenge and delegates to the repo.
func (a *MFAChallengeAdapter) StoreMFAChallenge(ctx context.Context, challengeID string, c service.MFAChallenge) error {
	return a.repo.StoreMFAChallenge(ctx, challengeID, MFAChallenge{
		UserID:    c.UserID,
		Email:     c.Email,
		DeviceID:  c.DeviceID,
		IPAddress: c.IPAddress,
		UserAgent: c.UserAgent,
	})
}

// SetMFAChallengeTTL delegates directly to the repo.
func (a *MFAChallengeAdapter) SetMFAChallengeTTL(ctx context.Context, challengeID string, ttl time.Duration) error {
	return a.repo.SetMFAChallengeTTL(ctx, challengeID, ttl)
}

// GetMFAChallenge retrieves and translates the challenge to a service.MFAChallenge.
func (a *MFAChallengeAdapter) GetMFAChallenge(ctx context.Context, challengeID string) (*service.MFAChallenge, error) {
	rc, err := a.repo.GetMFAChallenge(ctx, challengeID)
	if err != nil || rc == nil {
		return nil, err
	}
	return &service.MFAChallenge{
		UserID:    rc.UserID,
		Email:     rc.Email,
		DeviceID:  rc.DeviceID,
		IPAddress: rc.IPAddress,
		UserAgent: rc.UserAgent,
	}, nil
}
