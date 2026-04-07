package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/fraud-detection/iam-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Mock: UserRepository
// ---------------------------------------------------------------------------

type mockUserRepo struct{ mock.Mock }

func (m *mockUserRepo) Create(ctx context.Context, u *domain.User) error {
	args := m.Called(ctx, u)
	return args.Error(0)
}

func (m *mockUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepo) Update(ctx context.Context, u *domain.User) error {
	return m.Called(ctx, u).Error(0)
}

func (m *mockUserRepo) IncrementFailedAttempts(ctx context.Context, userID string) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *mockUserRepo) LockAccount(ctx context.Context, userID string, until time.Time) error {
	return m.Called(ctx, userID, until).Error(0)
}

func (m *mockUserRepo) ResetFailedAttempts(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

func (m *mockUserRepo) UpdateLastLogin(ctx context.Context, userID, ip string) error {
	return m.Called(ctx, userID, ip).Error(0)
}

func (m *mockUserRepo) UpdateMFASecret(ctx context.Context, userID, secret string, backupCodes []string) error {
	return m.Called(ctx, userID, secret, backupCodes).Error(0)
}

func (m *mockUserRepo) UpdatePassword(ctx context.Context, userID, newHash string) error {
	return m.Called(ctx, userID, newHash).Error(0)
}

func (m *mockUserRepo) List(ctx context.Context, roleFilter string, activeOnly bool, limit, offset int) ([]*domain.User, int, error) {
	args := m.Called(ctx, roleFilter, activeOnly, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*domain.User), args.Int(1), args.Error(2)
}

func (m *mockUserRepo) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	return m.Called(ctx, t).Error(0)
}

func (m *mockUserRepo) GetRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RefreshToken), args.Error(1)
}

func (m *mockUserRepo) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}

func (m *mockUserRepo) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

func (m *mockUserRepo) GetRolePermissions(ctx context.Context, roleName string) ([]domain.Permission, error) {
	args := m.Called(ctx, roleName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *mockUserRepo) LogAuditEvent(ctx context.Context, evt *domain.AuditEvent) error {
	return m.Called(ctx, evt).Error(0)
}

// ---------------------------------------------------------------------------
// Mock: TokenRepository (for TokenService)
// ---------------------------------------------------------------------------

type mockTokenRepo struct{ mock.Mock }

func (m *mockTokenRepo) BlockJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return m.Called(ctx, jti, ttl).Error(0)
}

func (m *mockTokenRepo) IsJTIBlocked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}

func (m *mockTokenRepo) TrackSession(ctx context.Context, userID, jti string, ttl time.Duration) error {
	return m.Called(ctx, userID, jti, ttl).Error(0)
}

func (m *mockTokenRepo) RevokeAllSessions(ctx context.Context, userID string, jtiTTL time.Duration) error {
	return m.Called(ctx, userID, jtiTTL).Error(0)
}

// ---------------------------------------------------------------------------
// Mock: RateLimiter
// ---------------------------------------------------------------------------

type mockRateLimiter struct{ mock.Mock }

func (m *mockRateLimiter) RecordLoginAttempt(ctx context.Context, email string, window time.Duration) (int64, error) {
	args := m.Called(ctx, email, window)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockRateLimiter) ResetLoginAttempts(ctx context.Context, email string) error {
	return m.Called(ctx, email).Error(0)
}

func (m *mockRateLimiter) GetLoginAttemptCount(ctx context.Context, email string) (int64, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(int64), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: MFAChallengeStore
// ---------------------------------------------------------------------------

type mockMFAStore struct{ mock.Mock }

func (m *mockMFAStore) StoreMFAChallenge(ctx context.Context, challengeID string, c service.MFAChallenge) error {
	return m.Called(ctx, challengeID, c).Error(0)
}

func (m *mockMFAStore) SetMFAChallengeTTL(ctx context.Context, challengeID string, ttl time.Duration) error {
	return m.Called(ctx, challengeID, ttl).Error(0)
}

func (m *mockMFAStore) GetMFAChallenge(ctx context.Context, challengeID string) (*service.MFAChallenge, error) {
	args := m.Called(ctx, challengeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.MFAChallenge), args.Error(1)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func buildServices(t *testing.T) (
	*service.AuthService,
	*mockUserRepo,
	*mockTokenRepo,
	*mockRateLimiter,
	*mockMFAStore,
) {
	t.Helper()

	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	rateLimiter := new(mockRateLimiter)
	mfaStore := new(mockMFAStore)

	tokenSvc := service.NewTokenService(
		"test-secret-at-least-32-characters!!",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
		tokenRepo,
	)
	mfaSvc := service.NewMFAService("TestIssuer")
	authSvc := service.NewAuthService(userRepo, tokenSvc, mfaSvc, rateLimiter, mfaStore)

	return authSvc, userRepo, tokenRepo, rateLimiter, mfaStore
}

func mustHashPassword(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 4) // cost 4 for speed in tests
	require.NoError(t, err)
	return string(h)
}

func validUser() *domain.User {
	return &domain.User{
		ID:           "user-123",
		Email:        "alice@example.com",
		Role:         domain.RoleAnalyst,
		Active:       true,
		MFAEnabled:   false,
		FailedAttempts: 0,
	}
}

// ---------------------------------------------------------------------------
// Register tests
// ---------------------------------------------------------------------------

func TestRegister_ValidInput(t *testing.T) {
	authSvc, userRepo, _, rateLimiter, _ := buildServices(t)
	ctx := context.Background()

	_ = rateLimiter // not called during Register

	userRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
	userRepo.On("LogAuditEvent", ctx, mock.AnythingOfType("*domain.AuditEvent")).Return(nil)

	u, err := authSvc.Register(ctx, "bob@example.com", "StrongP@ssw0rd!!", "", "")

	require.NoError(t, err)
	assert.NotEmpty(t, u.ID)
	assert.Equal(t, "bob@example.com", u.Email)
	assert.Equal(t, domain.RoleAnalyst, u.Role) // default role
	assert.True(t, u.Active)
	// Password must be stored hashed, never in plaintext
	assert.NotEqual(t, "StrongP@ssw0rd!!", u.PasswordHash)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("StrongP@ssw0rd!!")))

	userRepo.AssertExpectations(t)
}

func TestRegister_WeakPassword_TooShort(t *testing.T) {
	authSvc, _, _, _, _ := buildServices(t)
	ctx := context.Background()

	_, err := authSvc.Register(ctx, "bob@example.com", "Short1!", "", "")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok, "expected *domain.AuthError, got %T", err)
	assert.Equal(t, domain.ErrWeakPassword, authErr.Code)
}

func TestRegister_WeakPassword_NoSpecialChar(t *testing.T) {
	authSvc, _, _, _, _ := buildServices(t)
	ctx := context.Background()

	_, err := authSvc.Register(ctx, "bob@example.com", "NoSpecialChar1234", "", "")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrWeakPassword, authErr.Code)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	authSvc, userRepo, _, _, _ := buildServices(t)
	ctx := context.Background()

	emailTakenErr := domain.NewAuthError(domain.ErrEmailTaken, "email already registered")
	userRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(emailTakenErr)
	userRepo.On("LogAuditEvent", ctx, mock.AnythingOfType("*domain.AuditEvent")).Return(nil).Maybe()

	_, err := authSvc.Register(ctx, "existing@example.com", "StrongP@ssw0rd!!", "", "")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrEmailTaken, authErr.Code)
}

func TestRegister_InvalidEmail(t *testing.T) {
	authSvc, _, _, _, _ := buildServices(t)
	ctx := context.Background()

	_, err := authSvc.Register(ctx, "not-an-email", "StrongP@ssw0rd!!", "", "")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrInvalidCredentials, authErr.Code)
}

// ---------------------------------------------------------------------------
// Login tests
// ---------------------------------------------------------------------------

func TestLogin_Success(t *testing.T) {
	authSvc, userRepo, tokenRepo, rateLimiter, _ := buildServices(t)
	ctx := context.Background()

	u := validUser()
	u.PasswordHash = mustHashPassword(t, "CorrectP@ssword1!")

	perms := []domain.Permission{{Resource: "alerts", Action: "read"}}

	rateLimiter.On("RecordLoginAttempt", ctx, u.Email, mock.AnythingOfType("time.Duration")).Return(int64(1), nil)
	userRepo.On("GetByEmail", ctx, u.Email).Return(u, nil)
	userRepo.On("ResetFailedAttempts", ctx, u.ID).Return(nil)
	userRepo.On("UpdateLastLogin", ctx, u.ID, "127.0.0.1").Return(nil)
	userRepo.On("GetRolePermissions", ctx, string(u.Role)).Return(perms, nil)
	tokenRepo.On("TrackSession", ctx, u.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	userRepo.On("CreateRefreshToken", ctx, mock.AnythingOfType("*domain.RefreshToken")).Return(nil)
	userRepo.On("LogAuditEvent", ctx, mock.AnythingOfType("*domain.AuditEvent")).Return(nil)
	rateLimiter.On("ResetLoginAttempts", ctx, u.Email).Return(nil)

	result, err := authSvc.Login(ctx, u.Email, "CorrectP@ssword1!", "", "device-abc", "127.0.0.1", "TestAgent/1.0")

	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.False(t, result.MFARequired)
	assert.Equal(t, u, result.User)
	assert.Equal(t, perms, result.Permissions)
}

func TestLogin_WrongPassword(t *testing.T) {
	authSvc, userRepo, _, rateLimiter, _ := buildServices(t)
	ctx := context.Background()

	u := validUser()
	u.PasswordHash = mustHashPassword(t, "CorrectP@ssword1!")

	rateLimiter.On("RecordLoginAttempt", ctx, u.Email, mock.AnythingOfType("time.Duration")).Return(int64(1), nil)
	userRepo.On("GetByEmail", ctx, u.Email).Return(u, nil)
	userRepo.On("IncrementFailedAttempts", ctx, u.ID).Return(1, nil)
	userRepo.On("LogAuditEvent", ctx, mock.AnythingOfType("*domain.AuditEvent")).Return(nil)

	_, err := authSvc.Login(ctx, u.Email, "WrongP@ssword1!", "", "device-abc", "127.0.0.1", "TestAgent/1.0")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrInvalidCredentials, authErr.Code)
}

func TestLogin_LockedAccount(t *testing.T) {
	authSvc, userRepo, _, rateLimiter, _ := buildServices(t)
	ctx := context.Background()

	lockUntil := time.Now().Add(10 * time.Minute)
	u := validUser()
	u.LockedUntil = &lockUntil
	u.PasswordHash = mustHashPassword(t, "CorrectP@ssword1!")

	rateLimiter.On("RecordLoginAttempt", ctx, u.Email, mock.AnythingOfType("time.Duration")).Return(int64(1), nil)
	userRepo.On("GetByEmail", ctx, u.Email).Return(u, nil)
	userRepo.On("LogAuditEvent", ctx, mock.AnythingOfType("*domain.AuditEvent")).Return(nil)

	_, err := authSvc.Login(ctx, u.Email, "CorrectP@ssword1!", "", "device-abc", "127.0.0.1", "TestAgent/1.0")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrAccountLocked, authErr.Code)
}

func TestLogin_MFARequired_WhenNoCodeProvided(t *testing.T) {
	authSvc, userRepo, _, rateLimiter, mfaStore := buildServices(t)
	ctx := context.Background()

	u := validUser()
	u.MFAEnabled = true
	u.MFASecret = "JBSWY3DPEHPK3PXP" // dummy base32 secret
	u.PasswordHash = mustHashPassword(t, "CorrectP@ssword1!")

	rateLimiter.On("RecordLoginAttempt", ctx, u.Email, mock.AnythingOfType("time.Duration")).Return(int64(1), nil)
	userRepo.On("GetByEmail", ctx, u.Email).Return(u, nil)
	mfaStore.On("StoreMFAChallenge", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("service.MFAChallenge")).Return(nil)
	mfaStore.On("SetMFAChallengeTTL", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)

	result, err := authSvc.Login(ctx, u.Email, "CorrectP@ssword1!", "", "device-abc", "127.0.0.1", "TestAgent/1.0")

	require.NoError(t, err)
	assert.True(t, result.MFARequired)
	assert.NotEmpty(t, result.MFAChallengeID)
	assert.Empty(t, result.AccessToken)
}

func TestLogin_RateLimitExceeded(t *testing.T) {
	authSvc, _, _, rateLimiter, _ := buildServices(t)
	ctx := context.Background()

	rateLimiter.On("RecordLoginAttempt", ctx, "blocked@example.com", mock.AnythingOfType("time.Duration")).Return(int64(6), nil)

	_, err := authSvc.Login(ctx, "blocked@example.com", "anything", "", "", "", "")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrAccountLocked, authErr.Code)
}

// ---------------------------------------------------------------------------
// ValidateToken tests
// ---------------------------------------------------------------------------

func TestValidateToken_DelegatestoTokenService(t *testing.T) {
	authSvc, _, tokenRepo, _, _ := buildServices(t)
	ctx := context.Background()

	// Issue a real token so we can validate it
	u := validUser()
	perms := []domain.Permission{{Resource: "alerts", Action: "read"}}

	// TokenService needs TrackSession to not fail
	tokenRepo.On("TrackSession", ctx, u.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	tokenRepo.On("IsJTIBlocked", ctx, mock.AnythingOfType("string")).Return(false, nil)

	tokenSvc := service.NewTokenService(
		"test-secret-at-least-32-characters!!",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
		tokenRepo,
	)
	tokenStr, originalClaims, err := tokenSvc.IssueAccessToken(ctx, u, perms)
	require.NoError(t, err)

	// ValidateToken should delegate and return matching claims
	claims, err := authSvc.ValidateToken(ctx, tokenStr)

	require.NoError(t, err)
	assert.Equal(t, originalClaims.UserID, claims.UserID)
	assert.Equal(t, originalClaims.Email, claims.Email)
	assert.Equal(t, originalClaims.Role, claims.Role)
	assert.Equal(t, originalClaims.JTI, claims.JTI)

	tokenRepo.AssertExpectations(t)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	authSvc, _, _, _, _ := buildServices(t)
	ctx := context.Background()

	_, err := authSvc.ValidateToken(ctx, "not.a.valid.jwt")

	require.Error(t, err)
	authErr, ok := err.(*domain.AuthError)
	require.True(t, ok)
	assert.Equal(t, domain.ErrTokenInvalid, authErr.Code)
}
