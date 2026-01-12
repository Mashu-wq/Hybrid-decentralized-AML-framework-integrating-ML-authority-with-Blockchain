// repositories/permission_repo.go
package repositories

import (
	"iam-service/database"

	"github.com/jmoiron/sqlx"
)

type PermissionRepository interface {
	HasPermission(role, permission string) (bool, error)
	GetUserPermissions(userID string) ([]string, error)
	GetRolePermissions(role string) ([]string, error)
}

type permissionRepository struct {
	db *sqlx.DB
}

func NewPermissionRepository() PermissionRepository {
	return &permissionRepository{db: database.DB}
}

func (r *permissionRepository) HasPermission(role, permission string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM iam_schema.role_permissions rp
			JOIN iam_schema.permissions p ON rp.permission_id = p.id
			WHERE rp.role_id = (
				SELECT id FROM iam_schema.roles WHERE name = $1
			) AND p.action = $2
		)
	`
	
	err := r.db.Get(&exists, query, role, permission)
	return exists, err
}

func (r *permissionRepository) GetUserPermissions(userID string) ([]string, error) {
	var permissions []string
	query := `
		SELECT DISTINCT p.action
		FROM iam_schema.permissions p
		JOIN iam_schema.role_permissions rp ON p.id = rp.permission_id
		JOIN iam_schema.roles r ON rp.role_id = r.id
		JOIN iam_schema.user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`
	
	err := r.db.Select(&permissions, query, userID)
	return permissions, err
}

func (r *permissionRepository) GetRolePermissions(role string) ([]string, error) {
	var permissions []string
	query := `
		SELECT p.action
		FROM iam_schema.permissions p
		JOIN iam_schema.role_permissions rp ON p.id = rp.permission_id
		JOIN iam_schema.roles r ON rp.role_id = r.id
		WHERE r.name = $1
	`
	
	err := r.db.Select(&permissions, query, role)
	return permissions, err
}