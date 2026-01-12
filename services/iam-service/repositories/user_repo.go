// repositories/user_repo.go
package repositories

import (
	"database/sql"
	"errors"
	"time"

	"iam-service/database"
	"iam-service/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type UserRepository interface {
	Create(user *models.User) error
	FindByID(id string) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	UpdateLastLogin(userID string) error
	IncrementFailedAttempts(email string) error
	ResetFailedAttempts(email string) error
	LockAccount(email string, until time.Time) error
	List(limit, offset int, filters map[string]interface{}) ([]models.User, int, error)
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository() UserRepository {
	return &userRepository{db: database.DB}
}

func (r *userRepository) Create(user *models.User) error {
	query := `
		INSERT INTO iam_schema.users 
		(id, email, password_hash, role, mfa_enabled, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	
	_, err := r.db.Exec(query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.MFAEnabled,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)
	
	return err
}

func (r *userRepository) FindByID(id string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, email, password_hash, role, mfa_enabled, is_active, 
		       last_login, failed_attempts, locked_until, created_at, updated_at
		FROM iam_schema.users 
		WHERE id = $1 AND is_active = true
	`
	
	err := r.db.Get(&user, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	
	return &user, nil
}

func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, email, password_hash, role, mfa_enabled, is_active, 
		       last_login, failed_attempts, locked_until, created_at, updated_at
		FROM iam_schema.users 
		WHERE email = $1 AND is_active = true
	`
	
	err := r.db.Get(&user, query, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	
	return &user, nil
}

func (r *userRepository) Update(user *models.User) error {
	query := `
		UPDATE iam_schema.users 
		SET email = $1, role = $2, mfa_enabled = $3, is_active = $4,
		    updated_at = $5
		WHERE id = $6
	`
	
	user.UpdatedAt = time.Now()
	_, err := r.db.Exec(query,
		user.Email,
		user.Role,
		user.MFAEnabled,
		user.IsActive,
		user.UpdatedAt,
		user.ID,
	)
	
	return err
}

func (r *userRepository) UpdateLastLogin(userID string) error {
	query := `
		UPDATE iam_schema.users 
		SET last_login = $1, failed_attempts = 0, locked_until = NULL
		WHERE id = $2
	`
	
	_, err := r.db.Exec(query, time.Now(), userID)
	return err
}

func (r *userRepository) IncrementFailedAttempts(email string) error {
	query := `
		UPDATE iam_schema.users 
		SET failed_attempts = failed_attempts + 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE email = $1
	`
	
	_, err := r.db.Exec(query, email)
	return err
}

func (r *userRepository) ResetFailedAttempts(email string) error {
	query := `
		UPDATE iam_schema.users 
		SET failed_attempts = 0, locked_until = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE email = $1
	`
	
	_, err := r.db.Exec(query, email)
	return err
}

func (r *userRepository) LockAccount(email string, until time.Time) error {
	query := `
		UPDATE iam_schema.users 
		SET locked_until = $1, updated_at = CURRENT_TIMESTAMP
		WHERE email = $2
	`
	
	_, err := r.db.Exec(query, until, email)
	return err
}

func (r *userRepository) List(limit, offset int, filters map[string]interface{}) ([]models.User, int, error) {
	var users []models.User
	var total int
	
	baseQuery := "FROM iam_schema.users WHERE 1=1"
	countQuery := "SELECT COUNT(*) " + baseQuery
	selectQuery := `
		SELECT id, email, role, mfa_enabled, is_active, last_login, 
		       failed_attempts, created_at, updated_at
		` + baseQuery + " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
	
	// Build where clause based on filters
	queryParams := []interface{}{}
	paramCount := 3
	
	if role, ok := filters["role"]; ok {
		baseQuery += " AND role = $" + string(rune(paramCount))
		queryParams = append(queryParams, role)
		paramCount++
	}
	
	if active, ok := filters["active"]; ok {
		baseQuery += " AND is_active = $" + string(rune(paramCount))
		queryParams = append(queryParams, active)
		paramCount++
	}
	
	// Count total
	countParams := append([]interface{}{}, queryParams...)
	err := r.db.Get(&total, countQuery, countParams...)
	if err != nil {
		return nil, 0, err
	}
	
	// Get paginated results
	selectParams := append([]interface{}{limit, offset}, queryParams...)
	err = r.db.Select(&users, selectQuery, selectParams...)
	if err != nil {
		return nil, 0, err
	}
	
	return users, total, nil
}