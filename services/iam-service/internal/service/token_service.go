// Package service contains the IAM business logic layer.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// jwtClaims extends jwt.RegisteredClaims with IAM-specific fields.
type jwtClaims struct {
	jwt.RegisteredClaims
	UserID      string          `json:"uid"`
	Email       string          `json:"email"`
	Role        string          `json:"role"`
	Permissions []string        `json:"perms"`
}

// TokenService handles JWT access token and opaque refresh token lifecycle.
type TokenService struct {
	jwtSecret     []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	issuer        string
	tokenRepo     TokenRepository
}

// TokenRepository defines the storage interface for token revocation.
type TokenRepository interface {
	BlockJTI(ctx context.Context, jti string, ttl time.Duration) error
	IsJTIBlocked(ctx context.Context, jti string) (bool, error)
	TrackSession(ctx context.Context, userID, jti string, ttl time.Duration) error
	RevokeAllSessions(ctx context.Context, userID string, jtiTTL time.Duration) error
}

// NewTokenService constructs a TokenService.
func NewTokenService(
	jwtSecret string,
	accessTTL, refreshTTL time.Duration,
	issuer string,
	repo TokenRepository,
) *TokenService {
	return &TokenService{
		jwtSecret:  []byte(jwtSecret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		issuer:     issuer,
		tokenRepo:  repo,
	}
}

// IssueAccessToken creates a signed JWT access token for the given user.
// The JTI (JWT ID) is stored in Redis so it can be blocklisted on logout.
func (s *TokenService) IssueAccessToken(ctx context.Context, u *domain.User, perms []domain.Permission) (string, *domain.TokenClaims, error) {
	jti := uuid.New().String()
	now := time.Now()
	exp := now.Add(s.accessTTL)

	// Build permission strings ("resource:action")
	permStrings := make([]string, len(perms))
	for i, p := range perms {
		permStrings[i] = p.String()
	}

	claims := &jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:      u.ID,
		Email:       u.Email,
		Role:        string(u.Role),
		Permissions: permStrings,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", nil, fmt.Errorf("sign access token: %w", err)
	}

	// Track in Redis for logout invalidation
	if err := s.tokenRepo.TrackSession(ctx, u.ID, jti, s.accessTTL+time.Minute); err != nil {
		// Non-fatal — token is still valid, just won't be in session tracker
		// Log but continue
		_ = err
	}

	domainClaims := &domain.TokenClaims{
		UserID:      u.ID,
		Email:       u.Email,
		Role:        u.Role,
		Permissions: perms,
		IssuedAt:    now,
		ExpiresAt:   exp,
		JTI:         jti,
	}

	return signed, domainClaims, nil
}

// ValidateAccessToken parses and validates a JWT, checking signature, expiry,
// and the JTI blocklist. Returns nil claims and an error if invalid.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwtClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.jwtSecret, nil
		},
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if isExpiredError(err) {
			return nil, domain.NewAuthError(domain.ErrTokenExpired, "access token has expired")
		}
		return nil, domain.NewAuthError(domain.ErrTokenInvalid, "invalid access token")
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, domain.NewAuthError(domain.ErrTokenInvalid, "malformed token claims")
	}

	// Check JTI blocklist (O(1) Redis lookup — handles logout before expiry)
	blocked, err := s.tokenRepo.IsJTIBlocked(ctx, claims.ID)
	if err != nil {
		// Redis unavailable — fail open in dev, closed in production
		// TODO: make this configurable per environment
		return nil, fmt.Errorf("jti blocklist check: %w", err)
	}
	if blocked {
		return nil, domain.NewAuthError(domain.ErrTokenRevoked, "token has been revoked")
	}

	// Parse permissions
	perms := make([]domain.Permission, 0, len(claims.Permissions))
	for _, ps := range claims.Permissions {
		// Parse "resource:action"
		for i := 0; i < len(ps); i++ {
			if ps[i] == ':' {
				perms = append(perms, domain.Permission{
					Resource: ps[:i],
					Action:   ps[i+1:],
				})
				break
			}
		}
	}

	return &domain.TokenClaims{
		UserID:      claims.UserID,
		Email:       claims.Email,
		Role:        domain.Role(claims.Role),
		Permissions: perms,
		IssuedAt:    claims.IssuedAt.Time,
		ExpiresAt:   claims.ExpiresAt.Time,
		JTI:         claims.ID,
	}, nil
}

// IssueRefreshToken generates a cryptographically secure opaque refresh token.
// Returns the raw token (sent to client) and the SHA-256 hash (stored in DB).
func (s *TokenService) IssueRefreshToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 48) // 384 bits of entropy
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate refresh token entropy: %w", err)
	}
	rawToken = hex.EncodeToString(b)
	tokenHash = hashToken(rawToken)
	return rawToken, tokenHash, nil
}

// HashToken returns SHA-256 of a raw token string.
// Exported for use in other packages (e.g. when client submits a refresh token).
func HashToken(raw string) string {
	return hashToken(raw)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RevokeAccessToken adds the JTI to the blocklist for the remaining TTL.
func (s *TokenService) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return nil // already expired, no need to blocklist
	}
	return s.tokenRepo.BlockJTI(ctx, jti, remaining+time.Minute) // +1min buffer
}

// RevokeAllUserSessions invalidates all access tokens for a user.
func (s *TokenService) RevokeAllUserSessions(ctx context.Context, userID string) error {
	return s.tokenRepo.RevokeAllSessions(ctx, userID, s.accessTTL+time.Minute)
}

// RefreshTTL returns the configured refresh token TTL.
func (s *TokenService) RefreshTTL() time.Duration { return s.refreshTTL }

// AccessTTL returns the configured access token TTL.
func (s *TokenService) AccessTTL() time.Duration { return s.accessTTL }

func isExpiredError(err error) bool {
	return err != nil && (err.Error() == "token has expired" ||
		containsAny(err.Error(), "expired", "exp"))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
