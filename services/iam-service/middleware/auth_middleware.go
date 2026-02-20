// middleware/auth_middleware.go
package middleware

import (
	"errors"
	"net/http"
	"strings"

	"iam-service/internal/security"
	"iam-service/repositories"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrNoAuthHeader      = errors.New("authorization header is missing")
	ErrInvalidAuthHeader = errors.New("authorization header format must be Bearer {token}")
	ErrInvalidToken      = errors.New("invalid token")
	ErrExpiredToken      = errors.New("token has expired")
)

type AuthMiddleware struct {
	jwtManager     *security.JWTManager
	userRepo       repositories.UserRepository
	permissionRepo repositories.PermissionRepository
}

func NewAuthMiddleware(
	jwtManager *security.JWTManager,
	userRepo repositories.UserRepository,
	permissionRepo repositories.PermissionRepository,
) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:     jwtManager,
		userRepo:       userRepo,
		permissionRepo: permissionRepo,
	}
}


// Handler is the main authentication middleware
func (am *AuthMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := extractToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		claims, err := am.jwtManager.ValidateToken(token)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "token_expired",
					"message": ErrExpiredToken.Error(),
				})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "invalid_token",
					"message": ErrInvalidToken.Error(),
				})
			}
			c.Abort()
			return
		}

		// user_id claim comes from JWT as string
		userIDStr, ok := claims["user_id"].(string)
		if !ok || userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Convert string -> uuid.UUID (because repo now expects uuid.UUID)
		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Invalid user_id format in token",
			})
			c.Abort()
			return
		}

		// Get user from database
		user, err := am.userRepo.FindByID(userUUID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_found",
				"message": "User account not found",
			})
			c.Abort()
			return
		}

		// Check if user is active
		if !user.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "account_inactive",
				"message": "Account is inactive",
			})
			c.Abort()
			return
		}

		// Store string IDs in context (easy to reuse everywhere)
		c.Set("user_id", user.ID.String())
		c.Set("user_email", user.Email)
		c.Set("user_role", user.Role)
		c.Set("user", user)

		c.Next()
	}
}
// RequirePermission middleware checks if user has specific permission
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User role not found",
			})
			c.Abort()
			return
		}

		// Create permission repository
		permissionRepo := repositories.NewPermissionRepository()

		// Check permission
		hasPermission, err := permissionRepo.HasPermission(role.(string), permission)
		if err != nil || !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware checks if user has specific role
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User role not found",
			})
			c.Abort()
			return
		}

		if userRole != role {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Insufficient role privileges",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper function to extract token from Authorization header
func extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeader
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}