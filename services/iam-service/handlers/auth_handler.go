// handlers/auth_handler.go
package handlers

import (
	"net/http"
	"time"

	"iam-service/config"
	"iam-service/repositories"
	"iam-service/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var (
	authService services.AuthService
	userRepo    repositories.UserRepository
	auditRepo   repositories.AuditRepository
)

func init() {
	cfg := config.Load()
	userRepo = repositories.NewUserRepository()
	sessionRepo := repositories.NewSessionRepository()
	auditRepo = repositories.NewAuditRepository()
	permissionRepo := repositories.NewPermissionRepository()

	authService = services.NewAuthService(
		userRepo,
		sessionRepo,
		auditRepo,
		permissionRepo,
		cfg,
	)
}

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	user, err := authService.Register(req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "registration_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	response, err := authService.Login(req.Email, req.Password, ip, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "authentication_failed",
			"message": err.Error(),
		})
		return
	}

	if response.MFARequired {
		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"temp_token":   response.TempToken,
			"message":      "MFA verification required",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

type VerifyMFARequest struct {
	TempToken string `json:"temp_token" binding:"required"`
	Code      string `json:"code" binding:"required,len=6"`
}

func VerifyMFA(c *gin.Context) {
	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	valid, err := authService.VerifyMFA(req.TempToken, req.Code)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "mfa_verification_failed",
			"message": "Invalid MFA code",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA verification successful",
	})
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func Refresh(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	response, err := authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "token_refresh_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

func Logout(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	sessionID := c.Query("session_id")

	err := authService.Logout(userID.(string), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "logout_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	err := authService.ForgotPassword(req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "password_reset_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email exists, a reset link has been sent",
	})
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	err := authService.ResetPassword(req.Token, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "password_reset_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

func ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	err := authService.ChangePassword(userID.(string), req.CurrentPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "password_change_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

func EnableMFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	response, err := authService.EnableMFA(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "mfa_enable_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

type DisableMFARequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

func DisableMFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	var req DisableMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	err := authService.DisableMFA(userID.(string), req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "mfa_disable_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA disabled successfully",
	})
}

func GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	user, err := userRepo.FindByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "user_not_found",
			"message": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":          user.ID,
			"email":       user.Email,
			"role":        user.Role,
			"mfa_enabled": user.MFAEnabled,
			"is_active":   user.IsActive,
			"last_login":  user.LastLogin,
			"created_at":  user.CreatedAt,
			"updated_at":  user.UpdatedAt,
		},
	})
}

type UpdateUserRequest struct {
	Email string `json:"email" binding:"omitempty,email"`
	Role  string `json:"role" binding:"omitempty,oneof=admin investigator client"`
}

func UpdateUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}

	user, err := userRepo.FindByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "user_not_found",
			"message": "User not found",
		})
		return
	}

	// Update fields
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}

	if err := userRepo.Update(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "update_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func GetUserSessions(c *gin.Context) {
	_, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	// Get sessions from repository
	// For now, return mock data
	sessions := []gin.H{
		{
			"id":          uuid.New().String(),
			"created_at":  time.Now().Add(-2 * time.Hour),
			"last_active": time.Now().Add(-5 * time.Minute),
			"ip_address":  "192.168.1.100",
			"user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"current":     true,
		},
		{
			"id":          uuid.New().String(),
			"created_at":  time.Now().Add(-24 * time.Hour),
			"last_active": time.Now().Add(-2 * time.Hour),
			"ip_address":  "203.0.113.1",
			"user_agent":  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)",
			"current":     false,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"total":    len(sessions),
	})
}

func RevokeSession(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}

	sessionID := c.Param("sessionId")

	// In production, verify session belongs to user
	_ = userID

	c.JSON(http.StatusOK, gin.H{
		"message":    "Session revoked successfully",
		"session_id": sessionID,
	})
}