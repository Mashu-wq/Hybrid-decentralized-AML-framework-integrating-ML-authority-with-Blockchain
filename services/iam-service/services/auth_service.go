// services/auth_service.go
package services

import (
	"context"
	"crypto/rand"
	"encoding/base32"
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
	"iam-service/utils"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type AuthService interface {
	Register(email, password, firstName, lastName string) (*models.User, error)
	Login(email, password, ip, userAgent string) (*LoginResponse, error)
	VerifyMFA(userID, code string) (bool, error)
	RefreshToken(refreshToken string) (*TokenResponse, error)
	Logout(userID, sessionID string) error
	ForgotPassword(email string) error
	ResetPassword(token, newPassword string) error
	ChangePassword(userID, currentPassword, newPassword string) error
	EnableMFA(userID string) (*MFAResponse, error)
	DisableMFA(userID, code string) error
	GenerateBackupCodes(userID string) ([]string, error)
}

type authService struct {
	userRepo      repositories.UserRepository
	sessionRepo   repositories.SessionRepository
	auditRepo     repositories.AuditRepository
	permissionRepo repositories.PermissionRepository
	jwtManager    *security.JWTManager
	passwordPolicy *security.PasswordPolicy
	mfaService    *mfa.MFAService
	config        *config.Config
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
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	MFAEnabled bool     `json:"mfa_enabled"`
	CreatedAt time.Time `json:"created_at"`
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
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		auditRepo:     auditRepo,
		permissionRepo: permissionRepo,
		jwtManager:    jwtManager,
		passwordPolicy: passwordPolicy,
		mfaService:    mfaService,
		config:        config,
	}
}

func (s *authService) Register(email, password, firstName, lastName string) (*models.User, error) {
	// Validate email format
	if !utils.IsValidEmail(email) {
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
	passwordHash, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}
	
	// Create user
	user := &models.User{
		Email:        email,
		PasswordHash: passwordHash,
		Role:         "client", // Default role
		MFAEnabled:   false,
		IsActive:     true,
	}
	
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	
	// Log audit event
	s.auditRepo.Create(&models.AuditLog{
		UserID:    user.ID,
		EventType: "REGISTRATION",
		Action:    "USER_REGISTERED",
		Status:    "SUCCESS",
	})
	
	return user, nil
}

func (s *authService) Login(email, password, ip, userAgent string) (*LoginResponse, error) {
	// Check if account is locked
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Log failed attempt
		s.auditRepo.Create(&models.AuditLog{
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ip,
			UserAgent: userAgent,
			Status:    "FAILED",
			Details:   "User not found",
		})
		return nil, errors.New("invalid credentials")
	}
	
	// Check if account is locked
	if user.LockedUntil.After(time.Now()) {
		s.auditRepo.Create(&models.AuditLog{
			UserID:    user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ip,
			UserAgent: userAgent,
			Status:    "FAILED",
			Details:   "Account locked",
		})
		return nil, errors.New("account is locked")
	}
	
	// Verify password
	if !utils.CheckPasswordHash(password, user.PasswordHash) {
		// Increment failed attempts
		s.userRepo.IncrementFailedAttempts(email)
		
		// Lock account after 5 failed attempts
		if user.FailedAttempts >= 4 { // 4 because we just incremented to 5
			lockUntil := time.Now().Add(30 * time.Minute)
			s.userRepo.LockAccount(email, lockUntil)
		}
		
		s.auditRepo.Create(&models.AuditLog{
			UserID:    user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_FAILED",
			IPAddress: ip,
			UserAgent: userAgent,
			Status:    "FAILED",
			Details:   "Invalid password",
		})
		
		return nil, errors.New("invalid credentials")
	}
	
	// Reset failed attempts on successful login
	s.userRepo.ResetFailedAttempts(email)
	s.userRepo.UpdateLastLogin(user.ID)
	
	// Check if MFA is required
	if user.MFAEnabled {
		// Generate temporary token for MFA verification
		tempToken := generateTempToken()
		
		// Store temp token in Redis with 5-minute expiry
		ctx := context.Background()
		key := fmt.Sprintf("mfa_temp:%s", tempToken)
		database.RedisClient.Set(ctx, key, user.ID, 5*time.Minute)
		
		s.auditRepo.Create(&models.AuditLog{
			UserID:    user.ID,
			EventType: "AUTHENTICATION",
			Action:    "LOGIN_SUCCESS",
			IPAddress: ip,
			UserAgent: userAgent,
			Status:    "SUCCESS",
			Details:   "MFA required",
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
		UserID:       user.ID,
		SessionToken: utils.HashToken(accessToken),
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.RefreshExpiry) * time.Second),
	}
	
	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}
	
	// Log successful login
	s.auditRepo.Create(&models.AuditLog{
		UserID:    user.ID,
		EventType: "AUTHENTICATION",
		Action:    "LOGIN_SUCCESS",
		IPAddress: ip,
		UserAgent: userAgent,
		Status:    "SUCCESS",
	})
	
	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.JWTExpiry,
		User: &UserDTO{
			ID:         user.ID,
			Email:      user.Email,
			Role:       user.Role,
			MFAEnabled: user.MFAEnabled,
			CreatedAt:  user.CreatedAt,
		},
		MFARequired: false,
	}, nil
}

func (s *authService) VerifyMFA(tempToken, code string) (bool, error) {
	ctx := context.Background()
	
	// Get user ID from temp token
	key := fmt.Sprintf("mfa_temp:%s", tempToken)
	userID, err := database.RedisClient.Get(ctx, key).Result()
	if err != nil {
		return false, errors.New("invalid or expired token")
	}
	
	// Delete temp token
	database.RedisClient.Del(ctx, key)
	
	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return false, errors.New("user not found")
	}
	
	// Get MFA secret from database
	// In production, you'd fetch this from a secure storage
	var mfaSecret string
	query := "SELECT mfa_secret FROM iam_schema.users WHERE id = $1"
	err = database.DB.Get(&mfaSecret, query, user.ID)
	if err != nil {
		return false, errors.New("MFA not configured")
	}
	
	// Verify TOTP code
	if !totp.Validate(code, mfaSecret) {
		s.auditRepo.Create(&models.AuditLog{
			UserID:    user.ID,
			EventType: "AUTHENTICATION",
			Action:    "MFA_FAILED",
			Status:    "FAILED",
		})
		return false, errors.New("invalid MFA code")
	}
	
	s.auditRepo.Create(&models.AuditLog{
		UserID:    user.ID,
		EventType: "AUTHENTICATION",
		Action:    "MFA_SUCCESS",
		Status:    "SUCCESS",
	})
	
	return true, nil
}

func (s *authService) RefreshToken(refreshToken string) (*TokenResponse, error) {
	// Validate refresh token
	// In production, you'd validate against database/Redis
	
	// For now, we'll decode the token to get user ID
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}
	
	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid token claims")
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

func (s *authService) Logout(userID, sessionID string) error {
	if sessionID != "" {
		// Revoke specific session
		return s.sessionRepo.Delete(sessionID)
	}
	
	// Revoke all sessions for user
	return s.sessionRepo.DeleteByUserID(userID)
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
	database.RedisClient.Set(ctx, key, user.ID, 1*time.Hour)
	
	// In production, send email with reset link
	// resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)
	// SendResetEmail(user.Email, resetLink)
	
	s.auditRepo.Create(&models.AuditLog{
		UserID:    user.ID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_RESET_REQUESTED",
		Status:    "SUCCESS",
	})
	
	return nil
}

func (s *authService) ResetPassword(token, newPassword string) error {
	ctx := context.Background()
	
	// Get user ID from reset token
	key := fmt.Sprintf("pwd_reset:%s", token)
	userID, err := database.RedisClient.Get(ctx, key).Result()
	if err != nil {
		return errors.New("invalid or expired token")
	}
	
	// Delete token
	database.RedisClient.Del(ctx, key)
	
	// Validate new password
	if valid, errs := s.passwordPolicy.Validate(newPassword); !valid {
		return fmt.Errorf("password validation failed: %v", strings.Join(errs, ", "))
	}
	
	// Hash new password
	passwordHash, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}
	
	// Update user password
	query := "UPDATE iam_schema.users SET password_hash = $1 WHERE id = $2"
	_, err = database.DB.Exec(query, passwordHash, userID)
	if err != nil {
		return err
	}
	
	// Log password change
	s.auditRepo.Create(&models.AuditLog{
		UserID:    userID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_RESET",
		Status:    "SUCCESS",
	})
	
	return nil
}

func (s *authService) ChangePassword(userID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("user not found")
	}
	
	// Verify current password
	if !utils.CheckPasswordHash(currentPassword, user.PasswordHash) {
		return errors.New("current password is incorrect")
	}
	
	// Validate new password
	if valid, errs := s.passwordPolicy.Validate(newPassword); !valid {
		return fmt.Errorf("password validation failed: %v", strings.Join(errs, ", "))
	}
	
	// Hash new password
	passwordHash, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}
	
	// Update password
	query := "UPDATE iam_schema.users SET password_hash = $1 WHERE id = $2"
	_, err = database.DB.Exec(query, passwordHash, userID)
	if err != nil {
		return err
	}
	
	// Log password change
	s.auditRepo.Create(&models.AuditLog{
		UserID:    userID,
		EventType: "AUTHENTICATION",
		Action:    "PASSWORD_CHANGED",
		Status:    "SUCCESS",
	})
	
	return nil
}

func (s *authService) EnableMFA(userID string) (*MFAResponse, error) {
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
	query := `
		UPDATE iam_schema.users 
		SET mfa_enabled = true, mfa_secret = $1
		WHERE id = $2
	`
	_, err = database.DB.Exec(query, key.Secret(), user.ID)
	if err != nil {
		return nil, err
	}
	
	s.auditRepo.Create(&models.AuditLog{
		UserID:    userID,
		EventType: "SECURITY",
		Action:    "MFA_ENABLED",
		Status:    "SUCCESS",
	})
	
	return &MFAResponse{
		Secret:      key.Secret(),
		QRCode:      key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

func (s *authService) DisableMFA(userID, code string) error {
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
			UserID:    user.ID,
			EventType: "SECURITY",
			Action:    "MFA_DISABLE_FAILED",
			Status:    "FAILED",
		})
		return errors.New("invalid MFA code")
	}
	
	// Disable MFA
	query = `
		UPDATE iam_schema.users 
		SET mfa_enabled = false, mfa_secret = NULL
		WHERE id = $1
	`
	_, err = database.DB.Exec(query, user.ID)
	if err != nil {
		return err
	}
	
	s.auditRepo.Create(&models.AuditLog{
		UserID:    userID,
		EventType: "SECURITY",
		Action:    "MFA_DISABLED",
		Status:    "SUCCESS",
	})
	
	return nil
}

func (s *authService) GenerateBackupCodes(userID string) ([]string, error) {
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
		UserID:    userID,
		EventType: "SECURITY",
		Action:    "BACKUP_CODES_GENERATED",
		Status:    "SUCCESS",
	})
	
	return backupCodes, nil
}

func (s *authService) generateTokens(user *models.User) (string, string, error) {
	// Generate access token
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		return "", "", err
	}
	
	// Generate refresh token
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
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