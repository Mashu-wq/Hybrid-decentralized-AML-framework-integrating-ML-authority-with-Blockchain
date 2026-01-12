// repositories/audit_repo.go
package repositories

import (
	"encoding/json"
	"time"

	"iam-service/database"
	"iam-service/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type AuditRepository interface {
	Create(log *models.AuditLog) error
	FindByUserID(userID string, limit, offset int) ([]models.AuditLog, int, error)
	FindByEventType(eventType string, limit, offset int) ([]models.AuditLog, int, error)
	FindByDateRange(start, end time.Time, limit, offset int) ([]models.AuditLog, int, error)
}

type auditRepository struct {
	db *sqlx.DB
}

func NewAuditRepository() AuditRepository {
	return &auditRepository{db: database.DB}
}

func (r *auditRepository) Create(log *models.AuditLog) error {
	query := `
		INSERT INTO iam_schema.audit_logs 
		(id, user_id, event_type, action, ip_address, user_agent, resource, resource_id, details, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	
	log.ID = uuid.New().String()
	log.CreatedAt = time.Now()
	
	detailsJSON, _ := json.Marshal(log.Details)
	
	_, err := r.db.Exec(query,
		log.ID,
		log.UserID,
		log.EventType,
		log.Action,
		log.IPAddress,
		log.UserAgent,
		log.Resource,
		log.ResourceID,
		string(detailsJSON),
		log.Status,
		log.CreatedAt,
	)
	
	return err
}

func (r *auditRepository) FindByUserID(userID string, limit, offset int) ([]models.AuditLog, int, error) {
	var logs []models.AuditLog
	var total int
	
	// Get total count
	countQuery := "SELECT COUNT(*) FROM iam_schema.audit_logs WHERE user_id = $1"
	err := r.db.Get(&total, countQuery, userID)
	if err != nil {
		return nil, 0, err
	}
	
	// Get paginated results
	query := `
		SELECT id, user_id, event_type, action, ip_address, user_agent, 
		       resource, resource_id, details, status, created_at
		FROM iam_schema.audit_logs 
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	
	err = r.db.Select(&logs, query, userID, limit, offset)
	return logs, total, err
}

func (r *auditRepository) FindByEventType(eventType string, limit, offset int) ([]models.AuditLog, int, error) {
	var logs []models.AuditLog
	var total int
	
	countQuery := "SELECT COUNT(*) FROM iam_schema.audit_logs WHERE event_type = $1"
	err := r.db.Get(&total, countQuery, eventType)
	if err != nil {
		return nil, 0, err
	}
	
	query := `
		SELECT id, user_id, event_type, action, ip_address, user_agent, 
		       resource, resource_id, details, status, created_at
		FROM iam_schema.audit_logs 
		WHERE event_type = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	
	err = r.db.Select(&logs, query, eventType, limit, offset)
	return logs, total, err
}

func (r *auditRepository) FindByDateRange(start, end time.Time, limit, offset int) ([]models.AuditLog, int, error) {
	var logs []models.AuditLog
	var total int
	
	countQuery := "SELECT COUNT(*) FROM iam_schema.audit_logs WHERE created_at BETWEEN $1 AND $2"
	err := r.db.Get(&total, countQuery, start, end)
	if err != nil {
		return nil, 0, err
	}
	
	query := `
		SELECT id, user_id, event_type, action, ip_address, user_agent, 
		       resource, resource_id, details, status, created_at
		FROM iam_schema.audit_logs 
		WHERE created_at BETWEEN $1 AND $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	
	err = r.db.Select(&logs, query, start, end, limit, offset)
	return logs, total, err
}