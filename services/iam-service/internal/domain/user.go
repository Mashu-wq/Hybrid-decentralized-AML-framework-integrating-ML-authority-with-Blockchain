// Package domain contains the core IAM domain models.
// These types are persistence-agnostic — no DB tags or ORM coupling.
package domain

import (
	"time"
)

// Role defines the RBAC roles available in the system.
type Role string

const (
	RoleAdmin       Role = "ADMIN"
	RoleAnalyst     Role = "ANALYST"
	RoleInvestigator Role = "INVESTIGATOR"
	RoleAuditor     Role = "AUDITOR"
	RoleAPIClient   Role = "API_CLIENT"
)

// IsValid returns true if the role is one of the defined roles.
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleAnalyst, RoleInvestigator, RoleAuditor, RoleAPIClient:
		return true
	}
	return false
}

// Permission represents a single resource+action pair (e.g. alerts:read).
type Permission struct {
	Resource string
	Action   string
}

// String returns the canonical "resource:action" representation.
func (p Permission) String() string {
	return p.Resource + ":" + p.Action
}

// User is the core IAM domain entity.
type User struct {
	ID             string
	Email          string
	PasswordHash   string     // bcrypt, cost 12 — never expose in API responses
	Role           Role
	MFAEnabled     bool
	MFASecret      string     // TOTP base32 secret — encrypted at app layer before storage
	MFABackupCodes []string   // hashed one-time backup codes
	Active         bool
	FailedAttempts int
	LockedUntil    *time.Time
	LastLoginAt    *time.Time
	LastLoginIP    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsLocked returns true if the account is currently locked due to failed attempts.
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
}

// LockoutRemainingSeconds returns seconds until the lockout expires (0 if not locked).
func (u *User) LockoutRemainingSeconds() int64 {
	if !u.IsLocked() {
		return 0
	}
	return int64(time.Until(*u.LockedUntil).Seconds())
}

// RefreshToken represents a stored refresh token bound to a user + device.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string     // SHA-256 of the raw token — only hash is stored
	DeviceID  string
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// IsExpired returns true if the token has passed its expiry time.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRevoked returns true if the token has been explicitly revoked.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsValid returns true if the token can be used for refresh.
func (t *RefreshToken) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// AuditEvent records a security-relevant IAM event.
type AuditEvent struct {
	ID        int64
	UserID    string
	EventType AuditEventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string
	CreatedAt time.Time
}

// AuditEventType enumerates IAM audit event types.
type AuditEventType string

const (
	EventLoginSuccess    AuditEventType = "LOGIN_SUCCESS"
	EventLoginFailure    AuditEventType = "LOGIN_FAILURE"
	EventLoginLocked     AuditEventType = "LOGIN_LOCKED"
	EventLogout          AuditEventType = "LOGOUT"
	EventRegister        AuditEventType = "REGISTER"
	EventPasswordChanged AuditEventType = "PASSWORD_CHANGED"
	EventMFAEnabled      AuditEventType = "MFA_ENABLED"
	EventMFAVerified     AuditEventType = "MFA_VERIFIED"
	EventMFAFailed       AuditEventType = "MFA_FAILED"
	EventTokenRefreshed  AuditEventType = "TOKEN_REFRESHED"
	EventTokenRevoked    AuditEventType = "TOKEN_REVOKED"
	EventUserDeactivated AuditEventType = "USER_DEACTIVATED"
	EventUserUpdated     AuditEventType = "USER_UPDATED"
)

// TokenClaims holds the validated payload of a JWT access token.
type TokenClaims struct {
	UserID      string
	Email       string
	Role        Role
	Permissions []Permission
	IssuedAt    time.Time
	ExpiresAt   time.Time
	JTI         string // JWT ID — unique per token (used for revocation check)
}

// ErrCode defines machine-readable error codes returned to callers.
type ErrCode string

const (
	ErrInvalidCredentials ErrCode = "INVALID_CREDENTIALS"
	ErrAccountLocked      ErrCode = "ACCOUNT_LOCKED"
	ErrAccountInactive    ErrCode = "ACCOUNT_INACTIVE"
	ErrMFARequired        ErrCode = "MFA_REQUIRED"
	ErrMFAInvalid         ErrCode = "MFA_INVALID"
	ErrTokenExpired       ErrCode = "TOKEN_EXPIRED"
	ErrTokenInvalid       ErrCode = "TOKEN_INVALID"
	ErrTokenRevoked       ErrCode = "TOKEN_REVOKED"
	ErrEmailTaken         ErrCode = "EMAIL_ALREADY_REGISTERED"
	ErrUserNotFound       ErrCode = "USER_NOT_FOUND"
	ErrPermissionDenied   ErrCode = "PERMISSION_DENIED"
	ErrWeakPassword       ErrCode = "PASSWORD_TOO_WEAK"
	ErrInternal           ErrCode = "INTERNAL_ERROR"
)

// AuthError wraps an error with a machine-readable code.
type AuthError struct {
	Code    ErrCode
	Message string
}

func (e *AuthError) Error() string {
	return string(e.Code) + ": " + e.Message
}

// NewAuthError creates a new AuthError.
func NewAuthError(code ErrCode, msg string) *AuthError {
	return &AuthError{Code: code, Message: msg}
}
