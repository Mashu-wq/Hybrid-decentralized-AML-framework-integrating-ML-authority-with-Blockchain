// models/user.go
package models

import (
	"time"
)

type User struct {
	ID             string    `db:"id" json:"id"`
	Email          string    `db:"email" json:"email"`
	PasswordHash   string    `db:"password_hash" json:"-"`
	Role           string    `db:"role" json:"role"`
	MFAEnabled     bool      `db:"mfa_enabled" json:"mfa_enabled"`
	MFASecret      string    `db:"mfa_secret" json:"  -"`
	IsActive       bool      `db:"is_active" json:"is_active"`
	LastLogin      time.Time `db:"last_login" json:"last_login,omitempty"`
	FailedAttempts int       `db:"failed_attempts" json:"-"`
	LockedUntil    time.Time `db:"locked_until" json:"-"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

type RefreshToken struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	TokenHash    string    `db:"token_hash"`
	ExpiresAt    time.Time `db:"expires_at"`
	CreatedAt    time.Time `db:"created_at"`
}

type AuditLog struct {
	ID          string    `db:"id" json:"id"`
	UserID      string    `db:"user_id" json:"user_id,omitempty"`
	EventType   string    `db:"event_type" json:"event_type"`
	Action      string    `db:"action" json:"action"`
	IPAddress   string    `db:"ip_address" json:"ip_address,omitempty"`
	UserAgent   string    `db:"user_agent" json:"user_agent,omitempty"`
	Resource    string    `db:"resource" json:"resource,omitempty"`
	ResourceID  string    `db:"resource_id" json:"resource_id,omitempty"`
	Details     string    `db:"details" json:"details,omitempty"`
	Status      string    `db:"status" json:"status"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type Session struct {
	ID           string    `db:"id" json:"id"`
	UserID       string    `db:"user_id" json:"user_id"`
	SessionToken string    `db:"session_token" json:"-"`
	IPAddress    string    `db:"ip_address" json:"ip_address"`
	UserAgent    string    `db:"user_agent" json:"user_agent"`
	DeviceInfo   string    `db:"device_info" json:"device_info"`
	ExpiresAt    time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	LastActive   time.Time `db:"last_active" json:"last_active"`
}

type MFASecret struct {
	UserID      string   `db:"user_id"`
	Secret      string   `db:"secret"`
	BackupCodes []string `db:"backup_codes"`
	CreatedAt   time.Time `db:"created_at"`
}