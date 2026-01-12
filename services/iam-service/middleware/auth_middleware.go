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

		userID, ok := claims["user_id"].(string)
		if !ok || userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Get user from database
		user, err := am.userRepo.FindByID(userID)
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

		// Set user info in context
		c.Set("user_id", user.ID)
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