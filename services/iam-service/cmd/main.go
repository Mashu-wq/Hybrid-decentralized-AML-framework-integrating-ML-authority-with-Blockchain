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
	"iam-service/migrations"
	"iam-service/repositories"
	"iam-service/services"

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

	// ========== NEW: RUN MIGRATIONS FIRST ==========
	log.Println("Running database migrations...")
	if err := migrations.RunMigrations(cfg); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}
	log.Println("Migrations completed successfully")

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

	// Repositories (MUST be created AFTER database.Connect so database.DB is not nil)
	userRepo := repositories.NewUserRepository()
	sessionRepo := repositories.NewSessionRepository()
	auditRepo := repositories.NewAuditRepository()
	permissionRepo := repositories.NewPermissionRepository()

	// Services + Handlers (constructed with dependencies)
	authService := services.NewAuthService(userRepo, sessionRepo, auditRepo, permissionRepo, cfg)
	authHandler := handlers.NewAuthHandler(authService, userRepo)

	// Auth middleware (JWT + repos)
	jwtManager := security.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiry, cfg.RefreshExpiry)
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, userRepo, permissionRepo)

	// Public routes
	r.GET("/health", handlers.HealthCheck)

	r.POST("/api/v1/auth/register", authHandler.Register)
	r.POST("/api/v1/auth/login", authHandler.Login)
	r.POST("/api/v1/auth/refresh", authHandler.Refresh)
	r.POST("/api/v1/auth/verify-mfa", authHandler.VerifyMFA)
	r.POST("/api/v1/auth/forgot-password", authHandler.ForgotPassword)
	r.POST("/api/v1/auth/reset-password", authHandler.ResetPassword)

	// Protected routes
	api := r.Group("/api/v1")
	api.Use(authMiddleware.Handler())
	{
		// User management (now methods on authHandler)
		api.GET("/users/me", authHandler.GetCurrentUser)
		api.PUT("/users/me", authHandler.UpdateUser)
		api.POST("/users/me/change-password", authHandler.ChangePassword)
		api.POST("/users/me/enable-mfa", authHandler.EnableMFA)
		api.POST("/users/me/disable-mfa", authHandler.DisableMFA)
		api.GET("/users/me/sessions", authHandler.GetUserSessions)
		api.DELETE("/users/me/sessions/:sessionId", authHandler.RevokeSession)
		api.POST("/auth/logout", authHandler.Logout)

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

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
log.Printf("Server starting on %s in %s mode", addr, cfg.Env)

go func() {
	if err := r.Run(addr); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}()


	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
}
