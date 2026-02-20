// services/auth_service.go
package services

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"iam-service/config"
	"iam-service/database"
	"iam-service/internal/mfa"
	"iam-service/internal/security"
	"iam-service/models"
	"iam-service/repositories"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type AuthService interface {
	Register(email, password, firstName, lastName string) (*models.User, error)
	Login(email, password, ip, userAgent string) (*LoginResponse, error)
	VerifyMFA(tempToken, code string) (*LoginResponse, error) // Changed signature
	RefreshToken(refreshToken string) (*TokenResponse, error)
	Logout(userIDStr, sessionID string) error // Changed to string
	ForgotPassword(email string) error
	ResetPassword(token, newPassword string) error
	ChangePassword(userIDStr, currentPassword, newPassword string) error // Changed to string
	EnableMFA(userIDStr string) (*MFAResponse, error) // Changed to string
	DisableMFA(userIDStr, code string) error // Changed to string
	GenerateBackupCodes(userIDStr string) ([]string, error) // Changed to string
}

type authService struct {
	userRepo       repositories.UserRepository
	sessionRepo    repositories.SessionRepository
	auditRepo      repositories.AuditRepository
	permissionRepo repositories.PermissionRepository
	jwtManager     *security.JWTManager
	passwordPolicy *security.PasswordPolicy
	mfaService     *mfa.MFAService
	config         *config.Config
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	User         *UserDTO  `json:"user"`
	MFARequired  bool      `json:"mfa_required"`
	TempToken    string    `json:"temp_token,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type MFAResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

type UserDTO struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name,omitempty"`
	LastName   string    `json:"last_name,omitempty"`
	Role       string    `json:"role"`
	MFAEnabled bool      `json:"mfa_enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

func NewAuthService(
	userRepo repositories.UserRepository,
	sessionRepo repositories.SessionRepository,
	auditRepo repositories.AuditRepository,
	permissionRepo repositories.PermissionRepository,
	config *config.Config,
) AuthService {
	jwtManager := security.NewJWTManager(config.JWTSecret, config.JWTExpiry, config.RefreshExpiry)
	passwordPolicy := security.NewDefaultPasswordPolicy()
	mfaService := mfa.NewMFAService("IAM Service")

	return &authService{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		auditRepo:      auditRepo,
		permissionRepo: permissionRepo,
		jwtManager:     jwtManager,
		passwordPolicy: passwordPolicy,
		mfaService:     mfaService,
		config:         config,
	}
}

func (s *authService) Register(email, password, firstName, lastName string) (*models.User, error) {
	// Validate email format
	if !s.passwordPolicy.ValidateEmail(email) {
		return nil, errors.New("invalid email format")
	}

	// Check if user already exists
	existingUser, err := s.userRepo.FindByEmail(email)
	if existingUser != nil && err == nil {
		return nil, errors.New("user already exists")
	}

	// Validate password against policy
	if valid, errs := s.passwordPolicy.Validate(password); !valid {
		return nil, fmt.Errorf("password validation failed: %v", strings.Join(errs, ", "))
	}

	// Hash password
	passwordHash, err := s.passwordPolicy.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &models.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         "client", // Default role
		MFAEnabled:   false,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Log audit event
	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "REGISTRATION",
		Action:    "USER_REGISTERED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return user, nil
}

func (s *authService) Login(email, password, ip, userAgent string) (*LoginResponse, error) {
	var ipPtr *string
if ip != "" {
    ipPtr = &ip
}

var uaPtr *string
if userAgent != "" {
    uaPtr = &userAgent
}

	mkDetails := func(v any) json.RawMessage {
	b, _ := json.Marshal(v) // ignore marshal error safely (or handle if you want)
	return b
}

	// Check if account is locked
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Log failed attempt
		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ipPtr,
            UserAgent: uaPtr,
			Status:    "FAILED",
			Details:   mkDetails(gin.H{"reason": "user_not_found"}),
			CreatedAt: time.Now(),
		})
		return nil, errors.New("invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			UserID:    &user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ipPtr,
            UserAgent: uaPtr,
			Status:    "FAILED",
			Details:   mkDetails(gin.H{"reason": "account_locked", "locked_until": user.LockedUntil}),
			CreatedAt: time.Now(),
		})
		return nil, errors.New("account is locked")
	}

	// Verify password
	if !s.passwordPolicy.CheckPasswordHash(password, user.PasswordHash) {
		// Increment failed attempts
		s.userRepo.IncrementFailedAttempts(user.ID.String())

		// Lock account after 5 failed attempts
		if user.FailedAttempts >= 4 { // 4 because we just incremented to 5
			lockUntil := time.Now().Add(30 * time.Minute)
			s.userRepo.LockAccount(user.ID.String(), lockUntil)
		}

		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			UserID:    &user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ipPtr,
            UserAgent: uaPtr,
			Status:    "FAILED",
			Details:   mkDetails(gin.H{"reason": "invalid_password"}),
			CreatedAt: time.Now(),
		})

		return nil, errors.New("invalid credentials")
	}

	// Reset failed attempts on successful login
	s.userRepo.ResetFailedAttempts(user.ID.String())
	
	// Update last login
	now := time.Now()
	user.LastLogin = &now
	s.userRepo.UpdateLastLogin(user.ID)

	// Check if MFA is required
	if user.MFAEnabled {
		// Generate temporary token for MFA verification
		tempToken := generateTempToken()

		// Store temp token in Redis with 5-minute expiry
		ctx := context.Background()
		key := fmt.Sprintf("mfa_temp:%s", tempToken)
		database.RedisClient.Set(ctx, key, user.ID.String(), 5*time.Minute)

		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			UserID:    &user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_SUCCESS",
			IPAddress: ipPtr,
            UserAgent: uaPtr,
			Status:    "SUCCESS",
			Details:   mkDetails(gin.H{"mfa_required": true}),
			CreatedAt: time.Now(),
		})

		return &LoginResponse{
			MFARequired: true,
			TempToken:   tempToken,
		}, nil
	}

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, err
	}

	// Create session
	session := &models.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		SessionToken: s.jwtManager.HashToken(accessToken),
		IPAddress:    ipPtr,
		UserAgent:    uaPtr,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.RefreshExpiry) * time.Second),
		CreatedAt:    time.Now(),
		LastActive:   time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	// Log successful login
	s.auditRepo.Create(&models.AuditLog{
		//ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "AUTHENTICATION",
		Action:    "LOGIN_SUCCESS",
		IPAddress: ipPtr,
        UserAgent: uaPtr, 
		Status:    "SUCCESS",
		//CreatedAt: time.Now(),
	})

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWTExpiry,
		User: &UserDTO{
			ID:         user.ID.String(),
			Email:      user.Email,
			Role:       user.Role,
			MFAEnabled: user.MFAEnabled,
			CreatedAt:  user.CreatedAt,
		},
		MFARequired: false,
	}, nil
}

func (s *authService) VerifyMFA(tempToken, code string) (*LoginResponse, error) {
	ctx := context.Background()

	// Get user ID from temp token
	key := fmt.Sprintf("mfa_temp:%s", tempToken)
	userIDStr, err := database.RedisClient.Get(ctx, key).Result()
	if err != nil {
		return nil, errors.New("invalid or expired token")
	}

	// Delete temp token
	database.RedisClient.Del(ctx, key)

	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get MFA secret from database
	var mfaSecret string
	query := "SELECT mfa_secret FROM iam_schema.users WHERE id = $1"
	err = database.DB.Get(&mfaSecret, query, user.ID)
	if err != nil {
		return nil, errors.New("MFA not configured")
	}

	// Verify TOTP code
	if !totp.Validate(code, mfaSecret) {
		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			UserID:    &user.ID,
			EventType: "AUTHENTICATION",
			Action:    "MFA_FAILED",
			Status:    "FAILED",
			CreatedAt: time.Now(),
		})
		return nil, errors.New("invalid MFA code")
	}

	// Generate tokens for successful MFA verification
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, err
	}

	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "AUTHENTICATION",
		Action:    "MFA_SUCCESS",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	// Log successful login after MFA
	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "AUTHENTICATION",
		Action:    "LOGIN_SUCCESS",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWTExpiry,
		User: &UserDTO{
			ID:         user.ID.String(),
			Email:      user.Email,
			Role:       user.Role,
			MFAEnabled: user.MFAEnabled,
			CreatedAt:  user.CreatedAt,
		},
		MFARequired: false,
	}, nil
}

func (s *authService) RefreshToken(refreshToken string) (*TokenResponse, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new tokens
	accessToken, newRefreshToken, err := s.generateTokens(user)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWTExpiry,
	}, nil
}

func (s *authService) Logout(userIDStr, sessionID string) error {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user ID")
	}

	if sessionID != "" {
		// Parse session ID
		sessionUUID, err := uuid.Parse(sessionID)
		if err != nil {
			return errors.New("invalid session ID")
		}
		// Revoke specific session
		return s.sessionRepo.Delete(sessionUUID.String())
	}

	// Revoke all sessions for user
	return s.sessionRepo.DeleteByUserID(userID.String())
}

func (s *authService) ForgotPassword(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate reset token
	resetToken := generateResetToken()

	// Store token in Redis with 1-hour expiry
	ctx := context.Background()
	key := fmt.Sprintf("pwd_reset:%s", resetToken)
	database.RedisClient.Set(ctx, key, user.ID.String(), 1*time.Hour)

	// In production, send email with reset link
	// resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)
	// SendResetEmail(user.Email, resetLink)

	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_RESET_REQUESTED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *authService) ResetPassword(token, newPassword string) error {
	ctx := context.Background()

	// Get user ID from reset token
	key := fmt.Sprintf("pwd_reset:%s", token)
	userIDStr, err := database.RedisClient.Get(ctx, key).Result()
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Delete token
	database.RedisClient.Del(ctx, key)

	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user ID")
	}

	// Validate new password
	if valid, errs := s.passwordPolicy.Validate(newPassword); !valid {
		return fmt.Errorf("password validation failed: %v", strings.Join(errs, ", "))
	}

	// Hash new password
	passwordHash, err := s.passwordPolicy.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update user password
	query := "UPDATE iam_schema.users SET password_hash = $1, updated_at = $2 WHERE id = $3"
	_, err = database.DB.Exec(query, passwordHash, time.Now(), userID)
	if err != nil {
		return err
	}

	// Invalidate all user sessions
	s.sessionRepo.DeleteByUserID(userID.String())

	// Log password change
	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &userID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_RESET",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *authService) ChangePassword(userIDStr, currentPassword, newPassword string) error {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if !s.passwordPolicy.CheckPasswordHash(currentPassword, user.PasswordHash) {
		return errors.New("current password is incorrect")
	}

	// Validate new password
	if valid, errs := s.passwordPolicy.Validate(newPassword); !valid {
		return fmt.Errorf("password validation failed: %v", strings.Join(errs, ", "))
	}

	// Hash new password
	passwordHash, err := s.passwordPolicy.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password
	query := "UPDATE iam_schema.users SET password_hash = $1, updated_at = $2 WHERE id = $3"
	_, err = database.DB.Exec(query, passwordHash, time.Now(), userID)
	if err != nil {
		return err
	}

	// Invalidate all user sessions
	s.sessionRepo.DeleteByUserID(userID.String())

	// Log password change
	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &userID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_CHANGED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *authService) EnableMFA(userIDStr string) (*MFAResponse, error) {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if user.MFAEnabled {
		return nil, errors.New("MFA already enabled")
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "IAM Service",
		AccountName: user.Email,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}

	// Generate backup codes
	backupCodes := make([]string, 8)
	for i := 0; i < 8; i++ {
		backupCodes[i] = generateBackupCode()
	}

	// Store secret in database
	// In production, encrypt the secret before storing
	secret := key.Secret()
	query := `
		UPDATE iam_schema.users 
		SET mfa_enabled = true, mfa_secret = $1, updated_at = $2
		WHERE id = $3
	`
	_, err = database.DB.Exec(query, secret, time.Now(), user.ID)
	if err != nil {
		return nil, err
	}

	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "SECURITY",
		Action:    "MFA_ENABLED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return &MFAResponse{
		Secret:      key.Secret(),
		QRCode:      key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

func (s *authService) DisableMFA(userIDStr, code string) error {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user ID")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if !user.MFAEnabled {
		return errors.New("MFA not enabled")
	}

	// Get MFA secret
	var mfaSecret string
	query := "SELECT mfa_secret FROM iam_schema.users WHERE id = $1"
	err = database.DB.Get(&mfaSecret, query, user.ID)
	if err != nil {
		return errors.New("MFA not configured")
	}

	// Verify code
	if !totp.Validate(code, mfaSecret) {
		s.auditRepo.Create(&models.AuditLog{
			ID:        uuid.New(),
			UserID:    &user.ID,
			EventType: "SECURITY",
			Action:    "MFA_DISABLE_FAILED",
			Status:    "FAILED",
			CreatedAt: time.Now(),
		})
		return errors.New("invalid MFA code")
	}

	// Disable MFA
	query = `
		UPDATE iam_schema.users 
		SET mfa_enabled = false, mfa_secret = NULL, updated_at = $1
		WHERE id = $2
	`
	_, err = database.DB.Exec(query, time.Now(), user.ID)
	if err != nil {
		return err
	}

	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "SECURITY",
		Action:    "MFA_DISABLED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *authService) GenerateBackupCodes(userIDStr string) ([]string, error) {
	// Parse user ID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.MFAEnabled {
		return nil, errors.New("MFA not enabled")
	}

	// Generate new backup codes
	backupCodes := make([]string, 8)
	for i := 0; i < 8; i++ {
		backupCodes[i] = generateBackupCode()
	}

	// Store backup codes (hashed) in database
	// In production, hash the codes before storing

	s.auditRepo.Create(&models.AuditLog{
		ID:        uuid.New(),
		UserID:    &user.ID,
		EventType: "SECURITY",
		Action:    "BACKUP_CODES_GENERATED",
		Status:    "SUCCESS",
		CreatedAt: time.Now(),
	})

	return backupCodes, nil
}

func (s *authService) generateTokens(user *models.User) (string, string, error) {
	// Generate access token
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID.String(), user.Email, user.Role)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID.String())
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func generateTempToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func generateResetToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func generateBackupCode() string {
	b := make([]byte, 5)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}