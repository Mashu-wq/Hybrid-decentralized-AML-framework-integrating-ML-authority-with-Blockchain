// Package service contains the IAM business logic layer.
package service

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// -----------------------------------------------------------------------------
// Repository interface
// -----------------------------------------------------------------------------

// UserRepository defines the persistence interface required by AuthService.
// The postgres.UserRepo satisfies this interface.
type UserRepository interface {
	// User CRUD
	Create(ctx context.Context, u *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, u *domain.User) error

	// Account state mutations
	IncrementFailedAttempts(ctx context.Context, userID string) (int, error)
	LockAccount(ctx context.Context, userID string, until time.Time) error
	ResetFailedAttempts(ctx context.Context, userID string) error
	UpdateLastLogin(ctx context.Context, userID, ip string) error
	UpdateMFASecret(ctx context.Context, userID, secret string, backupCodes []string) error
	UpdatePassword(ctx context.Context, userID, newHash string) error

	// Listing
	List(ctx context.Context, roleFilter string, activeOnly bool, limit, offset int) ([]*domain.User, int, error)

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error

	// Permissions & audit
	GetRolePermissions(ctx context.Context, roleName string) ([]domain.Permission, error)
	LogAuditEvent(ctx context.Context, evt *domain.AuditEvent) error
}

// RateLimiter abstracts the Redis-backed login rate limiter so AuthService
// is not coupled to the Redis implementation.
type RateLimiter interface {
	RecordLoginAttempt(ctx context.Context, email string, window time.Duration) (int64, error)
	ResetLoginAttempts(ctx context.Context, email string) error
	GetLoginAttemptCount(ctx context.Context, email string) (int64, error)
}

// MFAChallengeStore stores and retrieves pending MFA challenges.
type MFAChallengeStore interface {
	StoreMFAChallenge(ctx context.Context, challengeID string, c MFAChallenge) error
	SetMFAChallengeTTL(ctx context.Context, challengeID string, ttl time.Duration) error
	GetMFAChallenge(ctx context.Context, challengeID string) (*MFAChallenge, error)
}

// MFAChallenge mirrors redis.MFAChallenge so the service layer has no Redis import.
type MFAChallenge struct {
	UserID    string
	Email     string
	DeviceID  string
	IPAddress string
	UserAgent string
}

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

// LoginResult is returned on a successful authentication.
type LoginResult struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  int64 // seconds
	RefreshExpiresIn int64 // seconds
	MFARequired      bool
	MFAChallengeID   string
	User             *domain.User
	Permissions      []domain.Permission
}

// RefreshResult is returned when rotating refresh tokens.
type RefreshResult struct {
	AccessToken      string
	NewRefreshToken  string
	AccessExpiresIn  int64 // seconds
}

// UserUpdates carries the subset of fields that can be updated via UpdateUser.
type UserUpdates struct {
	Role   *domain.Role
	Active *bool
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	maxFailedAttempts  = 5
	lockoutDuration    = 15 * time.Minute
	rateLimitWindow    = 15 * time.Minute
	mfaChallengeTTL    = 5 * time.Minute
	bcryptCost         = 12
	backupCodeCount    = 8
)

// -----------------------------------------------------------------------------
// AuthService
// -----------------------------------------------------------------------------

// AuthService implements all authentication and authorisation business logic.
// It is intentionally free of networking concerns — callers (gRPC handlers,
// HTTP handlers, tests) are responsible for transport-level concerns.
type AuthService struct {
	users        UserRepository
	tokenSvc     *TokenService
	mfaSvc       *MFAService
	rateLimiter  RateLimiter
	mfaStore     MFAChallengeStore
}

// NewAuthService constructs an AuthService with all required dependencies.
func NewAuthService(
	users UserRepository,
	tokenSvc *TokenService,
	mfaSvc *MFAService,
	rateLimiter RateLimiter,
	mfaStore MFAChallengeStore,
) *AuthService {
	return &AuthService{
		users:       users,
		tokenSvc:    tokenSvc,
		mfaSvc:      mfaSvc,
		rateLimiter: rateLimiter,
		mfaStore:    mfaStore,
	}
}

// -----------------------------------------------------------------------------
// Register
// -----------------------------------------------------------------------------

// Register creates a new user account.
// callerRole determines whether a non-default role can be assigned.
// Only ADMIN callers may set roles other than ANALYST.
func (s *AuthService) Register(ctx context.Context, email, password, role, callerRole string) (*domain.User, error) {
	// Validate email (simple format check — production would use a proper library)
	if !isValidEmail(email) {
		return nil, domain.NewAuthError(domain.ErrInvalidCredentials, "invalid email format")
	}

	// Validate password strength
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	// Determine role
	assignedRole := domain.RoleAnalyst // default
	if role != "" {
		r := domain.Role(strings.ToUpper(role))
		if !r.IsValid() {
			return nil, domain.NewAuthError(domain.ErrPermissionDenied, "invalid role: "+role)
		}
		if r != domain.RoleAnalyst && callerRole != string(domain.RoleAdmin) {
			return nil, domain.NewAuthError(domain.ErrPermissionDenied, "only ADMIN callers can assign non-default roles")
		}
		assignedRole = r
	}

	// Hash password — cost 12 is deliberately slow to resist brute-force
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	u := &domain.User{
		ID:           uuid.New().String(),
		Email:        strings.ToLower(strings.TrimSpace(email)),
		PasswordHash: string(hash),
		Role:         assignedRole,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, u); err != nil {
		return nil, err // includes ErrEmailTaken
	}

	// Audit log — password is NEVER included
	s.logAudit(ctx, u.ID, domain.EventRegister, "", "", map[string]string{
		"email": u.Email,
		"role":  string(u.Role),
	})

	log.Ctx(ctx).Info().
		Str("user_id", u.ID).
		Str("role", string(u.Role)).
		Msg("user registered")

	return u, nil
}

// -----------------------------------------------------------------------------
// Login
// -----------------------------------------------------------------------------

// Login authenticates a user by email/password, enforces rate limits and MFA.
func (s *AuthService) Login(ctx context.Context, email, password, mfaCode, deviceID, ip, userAgent string) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// --- Rate limit check ---
	count, err := s.rateLimiter.RecordLoginAttempt(ctx, email, rateLimitWindow)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("rate limiter error — failing open")
	} else if count > maxFailedAttempts {
		s.logAudit(ctx, "", domain.EventLoginLocked, ip, userAgent, map[string]string{"email": email, "reason": "rate_limit"})
		return nil, domain.NewAuthError(domain.ErrAccountLocked, "too many login attempts — try again later")
	}

	// --- Fetch user (no user enumeration: always return INVALID_CREDENTIALS for unknown email) ---
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		authErr, ok := err.(*domain.AuthError)
		if ok && authErr.Code == domain.ErrUserNotFound {
			return nil, domain.NewAuthError(domain.ErrInvalidCredentials, "invalid credentials")
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	// --- Account state checks ---
	if u.IsLocked() {
		s.logAudit(ctx, u.ID, domain.EventLoginLocked, ip, userAgent, map[string]string{
			"remaining_seconds": fmt.Sprintf("%d", u.LockoutRemainingSeconds()),
		})
		return nil, domain.NewAuthError(domain.ErrAccountLocked,
			fmt.Sprintf("account locked — try again in %d seconds", u.LockoutRemainingSeconds()))
	}
	if !u.Active {
		return nil, domain.NewAuthError(domain.ErrAccountInactive, "account is deactivated")
	}

	// --- Password verification ---
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return s.handleFailedLogin(ctx, u, ip, userAgent)
	}

	// --- MFA check ---
	if u.MFAEnabled {
		if mfaCode == "" {
			// No code provided — issue a challenge for the client to complete
			challengeID := uuid.New().String()
			challenge := MFAChallenge{
				UserID:    u.ID,
				Email:     u.Email,
				DeviceID:  deviceID,
				IPAddress: ip,
				UserAgent: userAgent,
			}
			if storeErr := s.mfaStore.StoreMFAChallenge(ctx, challengeID, challenge); storeErr != nil {
				return nil, fmt.Errorf("store mfa challenge: %w", storeErr)
			}
			if ttlErr := s.mfaStore.SetMFAChallengeTTL(ctx, challengeID, mfaChallengeTTL); ttlErr != nil {
				log.Ctx(ctx).Warn().Err(ttlErr).Msg("failed to set MFA challenge TTL")
			}
			return &LoginResult{MFARequired: true, MFAChallengeID: challengeID}, nil
		}

		// Code provided — verify it
		if !s.mfaSvc.Verify(u.MFASecret, mfaCode) {
			s.logAudit(ctx, u.ID, domain.EventMFAFailed, ip, userAgent, nil)
			return nil, domain.NewAuthError(domain.ErrMFAInvalid, "invalid MFA code")
		}
		s.logAudit(ctx, u.ID, domain.EventMFAVerified, ip, userAgent, nil)
	}

	return s.issueTokensAndFinishLogin(ctx, u, deviceID, ip, userAgent)
}

// handleFailedLogin increments counters, locks if threshold exceeded, logs audit.
func (s *AuthService) handleFailedLogin(ctx context.Context, u *domain.User, ip, userAgent string) (*LoginResult, error) {
	newCount, err := s.users.IncrementFailedAttempts(ctx, u.ID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", u.ID).Msg("failed to increment failed attempts")
	}

	if newCount >= maxFailedAttempts {
		lockUntil := time.Now().UTC().Add(lockoutDuration)
		if lockErr := s.users.LockAccount(ctx, u.ID, lockUntil); lockErr != nil {
			log.Ctx(ctx).Error().Err(lockErr).Str("user_id", u.ID).Msg("failed to lock account")
		}
		s.logAudit(ctx, u.ID, domain.EventLoginLocked, ip, userAgent, map[string]string{
			"failed_attempts": fmt.Sprintf("%d", newCount),
		})
	} else {
		s.logAudit(ctx, u.ID, domain.EventLoginFailure, ip, userAgent, map[string]string{
			"failed_attempts": fmt.Sprintf("%d", newCount),
		})
	}

	return nil, domain.NewAuthError(domain.ErrInvalidCredentials, "invalid credentials")
}

// issueTokensAndFinishLogin performs post-auth bookkeeping and issues tokens.
func (s *AuthService) issueTokensAndFinishLogin(ctx context.Context, u *domain.User, deviceID, ip, userAgent string) (*LoginResult, error) {
	// Reset rate limit and fail counter on success
	if err := s.rateLimiter.ResetLoginAttempts(ctx, u.Email); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to reset rate limit counter")
	}
	if err := s.users.ResetFailedAttempts(ctx, u.ID); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to reset failed attempts")
	}
	if err := s.users.UpdateLastLogin(ctx, u.ID, ip); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to update last login")
	}

	// Fetch permissions
	perms, err := s.users.GetRolePermissions(ctx, string(u.Role))
	if err != nil {
		return nil, fmt.Errorf("get permissions: %w", err)
	}

	// Issue access token
	accessToken, _, err := s.tokenSvc.IssueAccessToken(ctx, u, perms)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	// Issue refresh token
	rawRefresh, refreshHash, err := s.tokenSvc.IssueRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	now := time.Now().UTC()
	rt := &domain.RefreshToken{
		ID:        uuid.New().String(),
		UserID:    u.ID,
		TokenHash: refreshHash,
		DeviceID:  deviceID,
		IPAddress: ip,
		UserAgent: userAgent,
		ExpiresAt: now.Add(s.tokenSvc.RefreshTTL()),
		CreatedAt: now,
	}
	if err := s.users.CreateRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	s.logAudit(ctx, u.ID, domain.EventLoginSuccess, ip, userAgent, map[string]string{
		"device_id": deviceID,
	})

	return &LoginResult{
		AccessToken:      accessToken,
		RefreshToken:     rawRefresh,
		AccessExpiresIn:  int64(s.tokenSvc.AccessTTL().Seconds()),
		RefreshExpiresIn: int64(s.tokenSvc.RefreshTTL().Seconds()),
		User:             u,
		Permissions:      perms,
		MFARequired:      false,
	}, nil
}

// -----------------------------------------------------------------------------
// VerifyMFA
// -----------------------------------------------------------------------------

// VerifyMFA completes a pending MFA challenge and issues tokens.
func (s *AuthService) VerifyMFA(ctx context.Context, challengeID, mfaCode string) (*LoginResult, error) {
	challenge, err := s.mfaStore.GetMFAChallenge(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("get mfa challenge: %w", err)
	}
	if challenge == nil {
		return nil, domain.NewAuthError(domain.ErrMFAInvalid, "MFA challenge not found or expired")
	}

	u, err := s.users.GetByID(ctx, challenge.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user for mfa: %w", err)
	}

	if !s.mfaSvc.Verify(u.MFASecret, mfaCode) {
		s.logAudit(ctx, u.ID, domain.EventMFAFailed, challenge.IPAddress, challenge.UserAgent, nil)
		return nil, domain.NewAuthError(domain.ErrMFAInvalid, "invalid MFA code")
	}
	s.logAudit(ctx, u.ID, domain.EventMFAVerified, challenge.IPAddress, challenge.UserAgent, nil)

	return s.issueTokensAndFinishLogin(ctx, u, challenge.DeviceID, challenge.IPAddress, challenge.UserAgent)
}

// -----------------------------------------------------------------------------
// RefreshTokens
// -----------------------------------------------------------------------------

// RefreshTokens rotates the refresh token and issues a new access token.
// The old refresh token is revoked and a new one is created (token rotation).
func (s *AuthService) RefreshTokens(ctx context.Context, rawRefreshToken, deviceID string) (*RefreshResult, error) {
	tokenHash := HashToken(rawRefreshToken)

	rt, err := s.users.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if rt == nil {
		return nil, domain.NewAuthError(domain.ErrTokenInvalid, "refresh token not found")
	}
	if !rt.IsValid() {
		if rt.IsRevoked() {
			return nil, domain.NewAuthError(domain.ErrTokenRevoked, "refresh token has been revoked")
		}
		return nil, domain.NewAuthError(domain.ErrTokenExpired, "refresh token has expired")
	}
	// Verify device binding to prevent token theft across devices
	if rt.DeviceID != deviceID {
		// Suspicious — revoke the token immediately and alert via audit log
		_ = s.users.RevokeRefreshToken(ctx, tokenHash)
		s.logAudit(ctx, rt.UserID, domain.EventTokenRevoked, "", "", map[string]string{
			"reason":          "device_mismatch",
			"expected_device": rt.DeviceID,
			"presented_device": deviceID,
		})
		return nil, domain.NewAuthError(domain.ErrTokenInvalid, "device mismatch")
	}

	u, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user for refresh: %w", err)
	}
	if !u.Active {
		return nil, domain.NewAuthError(domain.ErrAccountInactive, "account is deactivated")
	}

	// Revoke old refresh token (rotation)
	if err := s.users.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	// Issue new refresh token
	newRawRefresh, newRefreshHash, err := s.tokenSvc.IssueRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("issue new refresh token: %w", err)
	}

	now := time.Now().UTC()
	newRT := &domain.RefreshToken{
		ID:        uuid.New().String(),
		UserID:    u.ID,
		TokenHash: newRefreshHash,
		DeviceID:  rt.DeviceID,
		IPAddress: rt.IPAddress,
		UserAgent: rt.UserAgent,
		ExpiresAt: now.Add(s.tokenSvc.RefreshTTL()),
		CreatedAt: now,
	}
	if err := s.users.CreateRefreshToken(ctx, newRT); err != nil {
		return nil, fmt.Errorf("store new refresh token: %w", err)
	}

	// Issue new access token
	perms, err := s.users.GetRolePermissions(ctx, string(u.Role))
	if err != nil {
		return nil, fmt.Errorf("get permissions: %w", err)
	}

	accessToken, _, err := s.tokenSvc.IssueAccessToken(ctx, u, perms)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	s.logAudit(ctx, u.ID, domain.EventTokenRefreshed, rt.IPAddress, rt.UserAgent, map[string]string{
		"device_id": rt.DeviceID,
	})

	return &RefreshResult{
		AccessToken:     accessToken,
		NewRefreshToken: newRawRefresh,
		AccessExpiresIn: int64(s.tokenSvc.AccessTTL().Seconds()),
	}, nil
}

// -----------------------------------------------------------------------------
// Logout
// -----------------------------------------------------------------------------

// Logout revokes the current access token JTI. If logoutAll is true, all
// sessions and all refresh tokens for the user are also revoked.
func (s *AuthService) Logout(ctx context.Context, userID, jti string, expiresAt time.Time, logoutAll bool) error {
	if err := s.tokenSvc.RevokeAccessToken(ctx, jti, expiresAt); err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}

	if logoutAll {
		if err := s.tokenSvc.RevokeAllUserSessions(ctx, userID); err != nil {
			log.Ctx(ctx).Error().Err(err).Str("user_id", userID).Msg("failed to revoke all sessions")
		}
		if err := s.users.RevokeAllUserTokens(ctx, userID); err != nil {
			log.Ctx(ctx).Error().Err(err).Str("user_id", userID).Msg("failed to revoke all refresh tokens")
		}
	}

	s.logAudit(ctx, userID, domain.EventLogout, "", "", map[string]string{
		"logout_all": fmt.Sprintf("%t", logoutAll),
		"jti":        jti,
	})
	return nil
}

// -----------------------------------------------------------------------------
// ChangePassword
// -----------------------------------------------------------------------------

// ChangePassword verifies the current password and replaces it with a new one.
func (s *AuthService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(currentPassword)); err != nil {
		return domain.NewAuthError(domain.ErrInvalidCredentials, "current password is incorrect")
	}

	if err := validatePasswordStrength(newPassword); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.users.UpdatePassword(ctx, userID, string(hash)); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	s.logAudit(ctx, userID, domain.EventPasswordChanged, "", "", nil)
	return nil
}

// -----------------------------------------------------------------------------
// Token validation (delegates to TokenService)
// -----------------------------------------------------------------------------

// ValidateToken parses and validates a JWT access token.
func (s *AuthService) ValidateToken(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
	return s.tokenSvc.ValidateAccessToken(ctx, tokenString)
}

// -----------------------------------------------------------------------------
// Permissions
// -----------------------------------------------------------------------------

// GetPermissions returns the permissions associated with a role string.
func (s *AuthService) GetPermissions(ctx context.Context, roleString string) ([]domain.Permission, error) {
	return s.users.GetRolePermissions(ctx, roleString)
}

// -----------------------------------------------------------------------------
// User management
// -----------------------------------------------------------------------------

// GetUser returns a user by ID.
func (s *AuthService) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return s.users.GetByID(ctx, userID)
}

// ListUsers returns a paginated, optionally filtered list of users.
func (s *AuthService) ListUsers(ctx context.Context, roleFilter string, activeOnly bool, limit, offset int) ([]*domain.User, int, error) {
	return s.users.List(ctx, roleFilter, activeOnly, limit, offset)
}

// UpdateUser applies a partial update to a user account.
func (s *AuthService) UpdateUser(ctx context.Context, userID string, updates UserUpdates) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	changed := false
	if updates.Role != nil && *updates.Role != u.Role {
		if !updates.Role.IsValid() {
			return domain.NewAuthError(domain.ErrPermissionDenied, "invalid role")
		}
		u.Role = *updates.Role
		changed = true
	}
	if updates.Active != nil && *updates.Active != u.Active {
		u.Active = *updates.Active
		changed = true
	}

	if !changed {
		return nil
	}

	if err := s.users.Update(ctx, u); err != nil {
		return err
	}

	s.logAudit(ctx, userID, domain.EventUserUpdated, "", "", nil)
	return nil
}

// DeactivateUser marks a user as inactive and revokes all their tokens.
func (s *AuthService) DeactivateUser(ctx context.Context, userID string) error {
	active := false
	if err := s.UpdateUser(ctx, userID, UserUpdates{Active: &active}); err != nil {
		return err
	}

	// Revoke all active sessions
	_ = s.tokenSvc.RevokeAllUserSessions(ctx, userID)
	_ = s.users.RevokeAllUserTokens(ctx, userID)

	s.logAudit(ctx, userID, domain.EventUserDeactivated, "", "", nil)
	return nil
}

// -----------------------------------------------------------------------------
// MFA setup
// -----------------------------------------------------------------------------

// SetupMFA generates a new TOTP secret and backup codes for a user.
// The caller is responsible for calling UpdateMFASecret on the repository after
// the user confirms the secret is saved in their authenticator app.
func (s *AuthService) SetupMFA(ctx context.Context, userID string) (secret, qrURL string, backupCodes []string, err error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", "", nil, err
	}

	secret, qrURL, err = s.mfaSvc.GenerateSecret(u.Email)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate MFA secret: %w", err)
	}

	rawCodes, hashedCodes, err := s.mfaSvc.GenerateBackupCodes(backupCodeCount)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate backup codes: %w", err)
	}

	if err := s.users.UpdateMFASecret(ctx, userID, secret, hashedCodes); err != nil {
		return "", "", nil, fmt.Errorf("store MFA secret: %w", err)
	}

	s.logAudit(ctx, userID, domain.EventMFAEnabled, "", "", nil)
	return secret, qrURL, rawCodes, nil
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

// logAudit writes a security audit event, ignoring non-fatal errors.
func (s *AuthService) logAudit(ctx context.Context, userID string, eventType domain.AuditEventType, ip, ua string, meta map[string]string) {
	evt := &domain.AuditEvent{
		UserID:    userID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.users.LogAuditEvent(ctx, evt); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("event_type", string(eventType)).Msg("failed to write audit event")
	}
}

// isValidEmail performs a simple structural check on email addresses.
// It does not validate deliverability — that requires an external service.
func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	atIdx := strings.Index(email, "@")
	if atIdx < 1 {
		return false
	}
	local := email[:atIdx]
	domain := email[atIdx+1:]
	if len(local) == 0 || len(domain) < 3 {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// validatePasswordStrength enforces the minimum password policy:
// at least 12 characters, with at least one upper, lower, digit, and special char.
func validatePasswordStrength(password string) error {
	if len(password) < 12 {
		return domain.NewAuthError(domain.ErrWeakPassword, "password must be at least 12 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if !hasSpecial {
		missing = append(missing, "special character")
	}

	if len(missing) > 0 {
		return domain.NewAuthError(domain.ErrWeakPassword,
			"password must contain at least one: "+strings.Join(missing, ", "))
	}
	return nil
}
