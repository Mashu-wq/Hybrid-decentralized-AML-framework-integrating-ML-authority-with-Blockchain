// handlers/secure_handler.go
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"iam-service/models"
	"iam-service/repositories"

	"github.com/gin-gonic/gin"
)

func ViewKYC(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}
	
	// In production, fetch KYC data based on user permissions
	c.JSON(http.StatusOK, gin.H{
		"message": "KYC data access successful",
		"user_id": userID,
		"data": []gin.H{
			{
				"id":           "kyc_001",
				"customer_id":  "cust_123",
				"status":       "verified",
				"verified_at":  "2024-01-15T10:30:00Z",
				"risk_level":   "low",
			},
		},
	})
}

func ViewAlerts(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not authenticated",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Alerts data access successful",
		"user_id": userID,
		"alerts": []gin.H{
			{
				"id":          "alert_001",
				"type":        "suspicious_transaction",
				"severity":    "high",
				"description": "Large transaction to high-risk country",
				"status":      "pending_review",
				"created_at":  "2024-01-15T11:30:00Z",
			},
		},
	})
}

func ListUsers(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit
	
	// Parse filters
	filters := make(map[string]interface{})
	if role := c.Query("role"); role != "" {
		filters["role"] = role
	}
	if active := c.Query("active"); active != "" {
		filters["active"] = active == "true"
	}
	
	userRepo := repositories.NewUserRepository()
	users, total, err := userRepo.List(limit, offset, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "list_users_failed",
			"message": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"pagination": gin.H{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"total_pages": (total + limit - 1) / limit,
		},
	})
}

func GetUser(c *gin.Context) {
	userID := c.Param("id")
	
	userRepo := repositories.NewUserRepository()
	user, err := userRepo.FindByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "user_not_found",
			"message": "User not found",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

type UpdateUserRoleRequest struct {
	Role string `json:"role" binding:"required,oneof=admin investigator client"`
}

func UpdateUserRole(c *gin.Context) {
	userID := c.Param("id")
	
	var req UpdateUserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": err.Error(),
		})
		return
	}
	
	userRepo := repositories.NewUserRepository()
	user, err := userRepo.FindByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "user_not_found",
			"message": "User not found",
		})
		return
	}
	
	user.Role = req.Role
	if err := userRepo.Update(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "update_failed",
			"message": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "User role updated successfully",
	})
}

func GetAuditLogs(c *gin.Context) {
	// Parse pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit
	
	auditRepo := repositories.NewAuditRepository()
	
	var logs []models.AuditLog
	var total int
	var err error
	
	// Filter by user_id if provided
	if userID := c.Query("user_id"); userID != "" {
		logs, total, err = auditRepo.FindByUserID(userID, limit, offset)
	} else if eventType := c.Query("event_type"); eventType != "" {
		logs, total, err = auditRepo.FindByEventType(eventType, limit, offset)
	} else {
		// Get all logs with pagination
		// In production, implement a proper FindAll method
		logs = []models.AuditLog{}
		total = 0
	}
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "get_audit_logs_failed",
			"message": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"pagination": gin.H{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"total_pages": (total + limit - 1) / limit,
		},
	})
}

func GetMetrics(c *gin.Context) {
	// In production, gather various metrics
	// For now, return mock data
	
	c.JSON(http.StatusOK, gin.H{
		"metrics": gin.H{
			"total_users": 150,
			"active_users": 120,
			"mfa_enabled": 80,
			"failed_logins_today": 5,
			"successful_logins_today": 350,
			"average_login_time_ms": 120,
		},
		"timestamp": "2024-01-15T12:00:00Z",
	})
}

func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "iam-service",
		"version":   "1.0.0",
	})
}