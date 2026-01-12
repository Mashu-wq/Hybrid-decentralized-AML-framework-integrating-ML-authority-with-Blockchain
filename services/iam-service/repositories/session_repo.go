// repositories/session_repo.go
package repositories

import (
	"time"

	"iam-service/database"
	"iam-service/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type SessionRepository interface {
	Create(session *models.Session) error
	FindByID(id string) (*models.Session, error)
	FindByUserID(userID string) ([]models.Session, error)
	Update(session *models.Session) error
	Delete(id string) error
	DeleteByUserID(userID string) error
	DeleteExpired() error
}

type sessionRepository struct {
	db *sqlx.DB
}

func NewSessionRepository() SessionRepository {
	return &sessionRepository{db: database.DB}
}

func (r *sessionRepository) Create(session *models.Session) error {
	query := `
		INSERT INTO iam_schema.sessions 
		(id, user_id, session_token, ip_address, user_agent, device_info, expires_at, created_at, last_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	session.ID = uuid.New().String()
	session.CreatedAt = time.Now()
	session.LastActive = time.Now()

	_, err := r.db.Exec(query,
		session.ID,
		session.UserID,
		session.SessionToken,
		session.IPAddress,
		session.UserAgent,
		session.DeviceInfo,
		session.ExpiresAt,
		session.CreatedAt,
		session.LastActive,
	)

	return err
}

func (r *sessionRepository) FindByID(id string) (*models.Session, error) {
	var session models.Session
	query := `
		SELECT id, user_id, session_token, ip_address, user_agent, device_info,
		       expires_at, created_at, last_active
		FROM iam_schema.sessions
		WHERE id = $1 AND expires_at > NOW()
	`

	err := r.db.Get(&session, query, id)
	return &session, err
}

func (r *sessionRepository) FindByUserID(userID string) ([]models.Session, error) {
	var sessions []models.Session
	query := `
		SELECT id, user_id, session_token, ip_address, user_agent, device_info,
		       expires_at, created_at, last_active
		FROM iam_schema.sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY last_active DESC
	`

	err := r.db.Select(&sessions, query, userID)
	return sessions, err
}

func (r *sessionRepository) Update(session *models.Session) error {
	query := `
		UPDATE iam_schema.sessions
		SET last_active = $1
		WHERE id = $2
	`

	session.LastActive = time.Now()
	_, err := r.db.Exec(query, session.LastActive, session.ID)
	return err
}

func (r *sessionRepository) Delete(id string) error {
	query := "DELETE FROM iam_schema.sessions WHERE id = $1"
	_, err := r.db.Exec(query, id)
	return err
}

func (r *sessionRepository) DeleteByUserID(userID string) error {
	query := "DELETE FROM iam_schema.sessions WHERE user_id = $1"
	_, err := r.db.Exec(query, userID)
	return err
}

func (r *sessionRepository) DeleteExpired() error {
	query := "DELETE FROM iam_schema.sessions WHERE expires_at < NOW()"
	_, err := r.db.Exec(query)
	return err
}