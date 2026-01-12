// cmd/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"iam-service/config"
	"iam-service/database"
	"iam-service/handlers"
	"iam-service/internal/security"
	"iam-service/middleware"
	"iam-service/repositories"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// Connect to database
	if err := database.Connect(cfg); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	// Initialize Redis for sessions
	if err := database.InitRedis(cfg); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}
	defer database.CloseRedis()

	// Initialize Elasticsearch for audit logs (optional)
	if cfg.ElasticsearchURL != "" {
		if err := database.InitElasticsearch(cfg); err != nil {
			log.Println("Elasticsearch not available, using database audit logs:", err)
		}
	}

	// Set Gin mode
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	r := gin.New()

	// Global middleware
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.RequestIDMiddleware())
	r.Use(middleware.SecurityHeadersMiddleware())

	// Initialize JWT manager and repositories for auth middleware
	jwtManager := security.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiry, cfg.RefreshExpiry)
	userRepo := repositories.NewUserRepository()
	permissionRepo := repositories.NewPermissionRepository()
	
	// Create auth middleware instance
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, userRepo, permissionRepo)

	// Public routes
	r.GET("/health", handlers.HealthCheck)
	r.POST("/api/v1/auth/register", handlers.Register)
	r.POST("/api/v1/auth/login", handlers.Login)
	r.POST("/api/v1/auth/refresh", handlers.Refresh)
	r.POST("/api/v1/auth/verify-mfa", handlers.VerifyMFA)
	r.POST("/api/v1/auth/forgot-password", handlers.ForgotPassword)
	r.POST("/api/v1/auth/reset-password", handlers.ResetPassword)

	// Protected routes
	api := r.Group("/api/v1")
	api.Use(authMiddleware.Handler())
	{
		// User management
		api.GET("/users/me", handlers.GetCurrentUser)
		api.PUT("/users/me", handlers.UpdateUser)
		api.POST("/users/me/change-password", handlers.ChangePassword)
		api.POST("/users/me/enable-mfa", handlers.EnableMFA)
		api.POST("/users/me/disable-mfa", handlers.DisableMFA)
		api.GET("/users/me/sessions", handlers.GetUserSessions)
		api.DELETE("/users/me/sessions/:sessionId", handlers.RevokeSession)
		api.POST("/auth/logout", handlers.Logout)

		// Business endpoints
		api.GET("/kyc", middleware.RequirePermission("VIEW_KYC"), handlers.ViewKYC)
		api.GET("/alerts", middleware.RequirePermission("VIEW_ALERTS"), handlers.ViewAlerts)

		// Admin routes
		admin := api.Group("/admin")
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("/users", handlers.ListUsers)
			admin.GET("/users/:id", handlers.GetUser)
			admin.PUT("/users/:id/role", handlers.UpdateUserRole)
			admin.GET("/audit-logs", handlers.GetAuditLogs)
			admin.GET("/metrics", handlers.GetMetrics)
		}
	}

	// Start server
	port := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Server starting on port %s in %s mode", cfg.Port, cfg.Env)

	// Graceful shutdown
	go func() {
		if err := r.Run(port); err != nil {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
}