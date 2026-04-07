// Package postgres implements IAM repository interfaces backed by PostgreSQL.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserRepo implements user persistence using pgx/v5 connection pool.
// All queries use parameterized statements — no string interpolation of user input.
type UserRepo struct {
	db *pgxpool.Pool
}

// NewUserRepo creates a new UserRepo backed by the given connection pool.
func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

// --- Write operations ---

// Create inserts a new user record into iam.users.
// Returns ErrEmailTaken if the email already exists.
func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	const q = `
		INSERT INTO iam.users
			(id, email, password_hash, role_id, mfa_enabled, active, failed_attempts, created_at, updated_at)
		VALUES
			($1, $2, $3,
			 (SELECT id FROM iam.roles WHERE name = $4),
			 $5, $6, $7, $8, $9)
	`
	_, err := r.db.Exec(ctx, q,
		u.ID, u.Email, u.PasswordHash, string(u.Role),
		u.MFAEnabled, u.Active, u.FailedAttempts,
		u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return domain.NewAuthError(domain.ErrEmailTaken, "email already registered")
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// Update persists changes to an existing user record.
func (r *UserRepo) Update(ctx context.Context, u *domain.User) error {
	const q = `
		UPDATE iam.users SET
			email           = $2,
			role_id         = (SELECT id FROM iam.roles WHERE name = $3),
			mfa_enabled     = $4,
			mfa_secret      = $5,
			active          = $6,
			failed_attempts = $7,
			locked_until    = $8,
			last_login_at   = $9,
			last_login_ip   = $10,
			updated_at      = NOW()
		WHERE id = $1
	`
	tag, err := r.db.Exec(ctx, q,
		u.ID, u.Email, string(u.Role),
		u.MFAEnabled, u.MFASecret, u.Active,
		u.FailedAttempts, u.LockedUntil, u.LastLoginAt, u.LastLoginIP,
	)
	if err != nil {
		return fmt.Errorf("update user %s: %w", u.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return domain.NewAuthError(domain.ErrUserNotFound, "user not found")
	}
	return nil
}

// IncrementFailedAttempts atomically increments failed login attempts.
// Returns the new count so the caller can decide whether to lock the account.
func (r *UserRepo) IncrementFailedAttempts(ctx context.Context, userID string) (int, error) {
	const q = `
		UPDATE iam.users
		SET failed_attempts = failed_attempts + 1, updated_at = NOW()
		WHERE id = $1
		RETURNING failed_attempts
	`
	var count int
	err := r.db.QueryRow(ctx, q, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	return count, nil
}

// LockAccount sets locked_until and resets failed_attempts.
func (r *UserRepo) LockAccount(ctx context.Context, userID string, until time.Time) error {
	const q = `
		UPDATE iam.users
		SET locked_until = $2, failed_attempts = 0, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, q, userID, until)
	if err != nil {
		return fmt.Errorf("lock account %s: %w", userID, err)
	}
	return nil
}

// ResetFailedAttempts resets the failed_attempts counter and clears locked_until.
func (r *UserRepo) ResetFailedAttempts(ctx context.Context, userID string) error {
	const q = `
		UPDATE iam.users
		SET failed_attempts = 0, locked_until = NULL, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, q, userID)
	return err
}

// UpdateLastLogin records the successful login timestamp and IP.
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID, ip string) error {
	const q = `
		UPDATE iam.users
		SET last_login_at = NOW(), last_login_ip = $2, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, q, userID, ip)
	return err
}

// UpdateMFASecret stores the TOTP secret (call after user confirms MFA setup).
func (r *UserRepo) UpdateMFASecret(ctx context.Context, userID, secret string, backupCodes []string) error {
	codesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("marshal backup codes: %w", err)
	}
	const q = `
		UPDATE iam.users
		SET mfa_secret = $2, mfa_backup_codes = $3, mfa_enabled = true, updated_at = NOW()
		WHERE id = $1
	`
	_, err = r.db.Exec(ctx, q, userID, secret, codesJSON)
	return err
}

// UpdatePassword replaces the password hash.
func (r *UserRepo) UpdatePassword(ctx context.Context, userID, newHash string) error {
	const q = `
		UPDATE iam.users
		SET password_hash = $2, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, q, userID, newHash)
	return err
}

// --- Read operations ---

// GetByID retrieves a user by primary key.
func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	const q = `
		SELECT u.id, u.email, u.password_hash, ro.name,
		       u.mfa_enabled, u.mfa_secret, u.mfa_backup_codes,
		       u.active, u.failed_attempts, u.locked_until,
		       u.last_login_at, u.last_login_ip, u.created_at, u.updated_at
		FROM iam.users u
		JOIN iam.roles ro ON ro.id = u.role_id
		WHERE u.id = $1
	`
	return r.scanUser(r.db.QueryRow(ctx, q, id))
}

// GetByEmail retrieves a user by email address (used during login).
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `
		SELECT u.id, u.email, u.password_hash, ro.name,
		       u.mfa_enabled, u.mfa_secret, u.mfa_backup_codes,
		       u.active, u.failed_attempts, u.locked_until,
		       u.last_login_at, u.last_login_ip, u.created_at, u.updated_at
		FROM iam.users u
		JOIN iam.roles ro ON ro.id = u.role_id
		WHERE u.email = $1
	`
	return r.scanUser(r.db.QueryRow(ctx, q, email))
}

// List returns a paginated list of users.
func (r *UserRepo) List(ctx context.Context, roleFilter string, activeOnly bool, limit, offset int) ([]*domain.User, int, error) {
	// Build WHERE clause
	where := "WHERE 1=1"
	args := []interface{}{}
	argN := 1

	if roleFilter != "" {
		where += fmt.Sprintf(" AND ro.name = $%d", argN)
		args = append(args, roleFilter)
		argN++
	}
	if activeOnly {
		where += fmt.Sprintf(" AND u.active = $%d", argN)
		args = append(args, true)
		argN++
	}

	// Count
	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM iam.users u JOIN iam.roles ro ON ro.id = u.role_id %s`, where)
	var total int
	if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	// Data
	args = append(args, limit, offset)
	dataQ := fmt.Sprintf(`
		SELECT u.id, u.email, u.password_hash, ro.name,
		       u.mfa_enabled, u.mfa_secret, u.mfa_backup_codes,
		       u.active, u.failed_attempts, u.locked_until,
		       u.last_login_at, u.last_login_ip, u.created_at, u.updated_at
		FROM iam.users u
		JOIN iam.roles ro ON ro.id = u.role_id
		%s ORDER BY u.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := r.scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

// --- Refresh tokens ---

// CreateRefreshToken persists a new refresh token record.
func (r *UserRepo) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	const q = `
		INSERT INTO iam.refresh_tokens
			(id, user_id, token_hash, device_id, ip_address, user_agent, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.Exec(ctx, q,
		t.ID, t.UserID, t.TokenHash, t.DeviceID,
		t.IPAddress, t.UserAgent, t.ExpiresAt, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken retrieves a refresh token by its SHA-256 hash.
func (r *UserRepo) GetRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, device_id, ip_address, user_agent,
		       expires_at, revoked_at, created_at
		FROM iam.refresh_tokens
		WHERE token_hash = $1
	`
	var t domain.RefreshToken
	err := r.db.QueryRow(ctx, q, tokenHash).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.DeviceID,
		&t.IPAddress, &t.UserAgent, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return &t, nil
}

// RevokeRefreshToken marks a specific token as revoked.
func (r *UserRepo) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	const q = `UPDATE iam.refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1`
	_, err := r.db.Exec(ctx, q, tokenHash)
	return err
}

// RevokeAllUserTokens revokes all active refresh tokens for a user (logout all devices).
func (r *UserRepo) RevokeAllUserTokens(ctx context.Context, userID string) error {
	const q = `
		UPDATE iam.refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`
	_, err := r.db.Exec(ctx, q, userID)
	return err
}

// --- Audit log ---

// LogAuditEvent persists a security audit event.
func (r *UserRepo) LogAuditEvent(ctx context.Context, evt *domain.AuditEvent) error {
	metaJSON, err := json.Marshal(evt.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	const q = `
		INSERT INTO iam.audit_log (user_id, event_type, ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = r.db.Exec(ctx, q,
		nilIfEmpty(evt.UserID), string(evt.EventType),
		nilIfEmpty(evt.IPAddress), nilIfEmpty(evt.UserAgent),
		metaJSON, evt.CreatedAt,
	)
	return err
}

// --- Permissions ---

// GetRolePermissions returns all permissions for a given role name.
func (r *UserRepo) GetRolePermissions(ctx context.Context, roleName string) ([]domain.Permission, error) {
	const q = `
		SELECT p.resource, p.action
		FROM iam.permissions p
		JOIN iam.role_permissions rp ON rp.permission_id = p.id
		JOIN iam.roles ro ON ro.id = rp.role_id
		WHERE ro.name = $1
		ORDER BY p.resource, p.action
	`
	rows, err := r.db.Query(ctx, q, roleName)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	defer rows.Close()

	var perms []domain.Permission
	for rows.Next() {
		var p domain.Permission
		if err := rows.Scan(&p.Resource, &p.Action); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// pgxRowScanner is satisfied by both pgx.Row and pgx.Rows.
type pgxRowScanner interface {
	Scan(dest ...interface{}) error
}

func (r *UserRepo) scanUser(row pgxRowScanner) (*domain.User, error) {
	var u domain.User
	var roleName string
	var mfaSecret *string
	var backupCodesJSON *[]byte

	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &roleName,
		&u.MFAEnabled, &mfaSecret, &backupCodesJSON,
		&u.Active, &u.FailedAttempts, &u.LockedUntil,
		&u.LastLoginAt, &u.LastLoginIP, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.NewAuthError(domain.ErrUserNotFound, "user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	u.Role = domain.Role(roleName)
	if mfaSecret != nil {
		u.MFASecret = *mfaSecret
	}
	if backupCodesJSON != nil {
		if err := json.Unmarshal(*backupCodesJSON, &u.MFABackupCodes); err != nil {
			return nil, fmt.Errorf("unmarshal backup codes: %w", err)
		}
	}
	return &u, nil
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "unique") || contains(err.Error(), "duplicate")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
