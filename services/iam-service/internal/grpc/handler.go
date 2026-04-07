// Package grpc — IAMService gRPC handler.
// Translates between proto request/response types and the service layer.
package grpc

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	iamv1 "github.com/fraud-detection/proto/gen/go/iam/v1"
	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/fraud-detection/iam-service/internal/service"
)

// AuthHandler implements iamv1.IAMServiceServer by delegating to AuthService.
type AuthHandler struct {
	iamv1.UnimplementedIAMServiceServer
	authSvc  *service.AuthService
	tokenSvc *service.TokenService
	log      zerolog.Logger
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(authSvc *service.AuthService, tokenSvc *service.TokenService, log zerolog.Logger) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, tokenSvc: tokenSvc, log: log}
}

// Register creates a new user account.
func (h *AuthHandler) Register(ctx context.Context, req *iamv1.RegisterRequest) (*iamv1.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	callerRole := ""
	if req.Meta != nil {
		callerRole = req.Meta.Role
	}

	u, err := h.authSvc.Register(ctx, req.Email, req.Password, req.Role, callerRole)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.RegisterResponse{
		UserId:    u.ID,
		Email:     u.Email,
		Role:      string(u.Role),
		CreatedAt: u.CreatedAt,
	}, nil
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(ctx context.Context, req *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	result, err := h.authSvc.Login(ctx,
		req.Email, req.Password, req.MfaCode,
		req.DeviceId, req.IpAddress, req.UserAgent,
	)
	if err != nil {
		return nil, mapAuthError(err)
	}

	resp := &iamv1.LoginResponse{
		MfaRequired:    result.MFARequired,
		MfaChallengeId: result.MFAChallengeID,
		TokenType:      "Bearer",
	}

	if !result.MFARequired {
		resp.AccessToken = result.AccessToken
		resp.RefreshToken = result.RefreshToken
		resp.AccessExpiresIn = result.AccessExpiresIn
		resp.RefreshExpiresIn = result.RefreshExpiresIn
		if result.User != nil {
			resp.User = domainUserToProto(result.User)
		}
	}

	return resp, nil
}

// RefreshToken rotates a refresh token and issues a new access token.
func (h *AuthHandler) RefreshToken(ctx context.Context, req *iamv1.RefreshTokenRequest) (*iamv1.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	result, err := h.authSvc.RefreshTokens(ctx, req.RefreshToken, req.DeviceId)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.RefreshTokenResponse{
		AccessToken:     result.AccessToken,
		RefreshToken:    result.NewRefreshToken,
		AccessExpiresIn: result.AccessExpiresIn,
	}, nil
}

// MFASetup generates TOTP credentials for a user.
func (h *AuthHandler) MFASetup(ctx context.Context, req *iamv1.MFASetupRequest) (*iamv1.MFASetupResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	secret, qrURL, backupCodes, err := h.authSvc.SetupMFA(ctx, req.UserId)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.MFASetupResponse{
		Secret:      secret,
		QrCodeUrl:   qrURL,
		BackupCodes: backupCodes,
	}, nil
}

// MFAVerify completes a pending MFA challenge.
func (h *AuthHandler) MFAVerify(ctx context.Context, req *iamv1.MFAVerifyRequest) (*iamv1.MFAVerifyResponse, error) {
	if req.MfaChallengeId == "" || req.TotpCode == "" {
		return nil, status.Error(codes.InvalidArgument, "mfa_challenge_id and totp_code are required")
	}

	result, err := h.authSvc.VerifyMFA(ctx, req.MfaChallengeId, req.TotpCode)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.MFAVerifyResponse{
		AccessToken:     result.AccessToken,
		RefreshToken:    result.RefreshToken,
		AccessExpiresIn: result.AccessExpiresIn,
		MfaEnabled:      true,
	}, nil
}

// Logout revokes the current session.
func (h *AuthHandler) Logout(ctx context.Context, req *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	// Extract user ID and JTI from context (set by auth interceptor after ValidateToken).
	// For logout we need the JTI from the access token presented in the Authorization header.
	// The token has already been validated by the auth interceptor at this point.
	userID := ""
	if req.Meta != nil {
		userID = req.Meta.UserId
	}
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required in request metadata")
	}

	// Re-validate the access token to extract JTI for blocklisting.
	// The auth interceptor has already validated it; we need to re-parse for JTI.
	// In production this would be extracted from context rather than re-parsed.
	// TODO: propagate JTI through context in auth interceptor (Phase 11 refinement)

	// JTI is not propagated through context yet (Phase 11 refinement).
	// Use worst-case expiry (now + accessTTL) for the blocklist TTL.
	worstCaseExpiry := time.Now().Add(h.tokenSvc.AccessTTL())
	if err := h.authSvc.Logout(ctx, userID, "", worstCaseExpiry, req.AllDevices); err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.LogoutResponse{Success: true}, nil
}

// ChangePassword updates a user's password after verifying the current one.
func (h *AuthHandler) ChangePassword(ctx context.Context, req *iamv1.ChangePasswordRequest) (*iamv1.ChangePasswordResponse, error) {
	if req.UserId == "" || req.CurrentPassword == "" || req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, current_password, and new_password are required")
	}

	if err := h.authSvc.ChangePassword(ctx, req.UserId, req.CurrentPassword, req.NewPassword); err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.ChangePasswordResponse{Success: true}, nil
}

// GetProfile returns the public profile for a user.
func (h *AuthHandler) GetProfile(ctx context.Context, req *iamv1.GetProfileRequest) (*iamv1.GetProfileResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	u, err := h.authSvc.GetUser(ctx, req.UserId)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.GetProfileResponse{Profile: domainUserToProto(u)}, nil
}

// ValidateToken is called by the API Gateway on every inbound request.
// It must be extremely fast — returns user ID, role, and permissions.
func (h *AuthHandler) ValidateToken(ctx context.Context, req *iamv1.ValidateTokenRequest) (*iamv1.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return &iamv1.ValidateTokenResponse{
			Valid:     false,
			ErrorCode: string(domain.ErrTokenInvalid),
		}, nil
	}

	claims, err := h.authSvc.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		authErr, ok := err.(*domain.AuthError)
		errCode := string(domain.ErrTokenInvalid)
		if ok {
			errCode = string(authErr.Code)
		}
		return &iamv1.ValidateTokenResponse{
			Valid:     false,
			ErrorCode: errCode,
		}, nil
	}

	perms := make([]string, len(claims.Permissions))
	for i, p := range claims.Permissions {
		perms[i] = p.String()
	}

	return &iamv1.ValidateTokenResponse{
		Valid:       true,
		UserId:      claims.UserID,
		Email:       claims.Email,
		Role:        string(claims.Role),
		Permissions: perms,
		ExpiresAt:   claims.ExpiresAt,
	}, nil
}

// GetPermissions returns the permissions for a given role.
func (h *AuthHandler) GetPermissions(ctx context.Context, req *iamv1.GetPermissionsRequest) (*iamv1.GetPermissionsResponse, error) {
	if req.Role == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}

	perms, err := h.authSvc.GetPermissions(ctx, req.Role)
	if err != nil {
		return nil, mapAuthError(err)
	}

	protoPerms := make([]*iamv1.Permission, len(perms))
	for i, p := range perms {
		protoPerms[i] = &iamv1.Permission{Resource: p.Resource, Action: p.Action}
	}

	return &iamv1.GetPermissionsResponse{Permissions: protoPerms}, nil
}

// ListUsers returns a paginated, optionally filtered list of users. Admin only.
func (h *AuthHandler) ListUsers(ctx context.Context, req *iamv1.ListUsersRequest) (*iamv1.ListUsersResponse, error) {
	limit, offset := 20, 0
	if req.Page != nil {
		if req.Page.PageSize > 0 {
			limit = int(req.Page.PageSize)
		}
	}

	users, total, err := h.authSvc.ListUsers(ctx, req.RoleFilter, req.ActiveOnly, limit, offset)
	if err != nil {
		return nil, mapAuthError(err)
	}

	profiles := make([]*iamv1.UserProfile, len(users))
	for i, u := range users {
		profiles[i] = domainUserToProto(u)
	}

	return &iamv1.ListUsersResponse{
		Users: profiles,
		Page: &commonv1.PageResponse{
			TotalCount: int32(total),
		},
	}, nil
}

// UpdateUser modifies a user's role or active status. Admin only.
func (h *AuthHandler) UpdateUser(ctx context.Context, req *iamv1.UpdateUserRequest) (*iamv1.UpdateUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	updates := service.UserUpdates{}
	if req.Role != "" {
		r := domain.Role(req.Role)
		updates.Role = &r
	}
	active := req.Active
	updates.Active = &active

	if err := h.authSvc.UpdateUser(ctx, req.UserId, updates); err != nil {
		return nil, mapAuthError(err)
	}

	u, err := h.authSvc.GetUser(ctx, req.UserId)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.UpdateUserResponse{User: domainUserToProto(u)}, nil
}

// DeactivateUser disables a user account and revokes all tokens. Admin only.
func (h *AuthHandler) DeactivateUser(ctx context.Context, req *iamv1.DeactivateUserRequest) (*iamv1.DeactivateUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	if err := h.authSvc.DeactivateUser(ctx, req.UserId); err != nil {
		return nil, mapAuthError(err)
	}

	return &iamv1.DeactivateUserResponse{Success: true}, nil
}

// HealthCheck reports service liveness.
func (h *AuthHandler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	return &commonv1.HealthCheckResponse{
		Status:  commonv1.HealthStatus_HEALTH_STATUS_SERVING,
		Details: "iam-service healthy",
	}, nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// domainUserToProto converts a domain.User to its proto representation.
func domainUserToProto(u *domain.User) *iamv1.UserProfile {
	p := &iamv1.UserProfile{
		Id:         u.ID,
		Email:      u.Email,
		Role:       string(u.Role),
		MfaEnabled: u.MFAEnabled,
		Active:     u.Active,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
	if u.LastLoginAt != nil {
		p.LastLoginAt = u.LastLoginAt
	}
	return p
}

// mapAuthError converts domain AuthErrors to gRPC status codes.
func mapAuthError(err error) error {
	if err == nil {
		return nil
	}

	authErr, ok := err.(*domain.AuthError)
	if !ok {
		return status.Errorf(codes.Internal, "internal error: %v", err)
	}

	switch authErr.Code {
	case domain.ErrInvalidCredentials:
		return status.Error(codes.Unauthenticated, authErr.Message)
	case domain.ErrAccountLocked:
		return status.Error(codes.ResourceExhausted, authErr.Message)
	case domain.ErrAccountInactive:
		return status.Error(codes.PermissionDenied, authErr.Message)
	case domain.ErrMFARequired:
		return status.Error(codes.FailedPrecondition, authErr.Message)
	case domain.ErrMFAInvalid:
		return status.Error(codes.Unauthenticated, authErr.Message)
	case domain.ErrTokenExpired:
		return status.Error(codes.Unauthenticated, authErr.Message)
	case domain.ErrTokenInvalid, domain.ErrTokenRevoked:
		return status.Error(codes.Unauthenticated, authErr.Message)
	case domain.ErrEmailTaken:
		return status.Error(codes.AlreadyExists, authErr.Message)
	case domain.ErrUserNotFound:
		return status.Error(codes.NotFound, authErr.Message)
	case domain.ErrPermissionDenied:
		return status.Error(codes.PermissionDenied, authErr.Message)
	case domain.ErrWeakPassword:
		return status.Error(codes.InvalidArgument, authErr.Message)
	default:
		return status.Errorf(codes.Internal, "internal error: %s", authErr.Message)
	}
}

// ensure AuthHandler satisfies the interface at compile time.
var _ iamv1.IAMServiceServer = (*AuthHandler)(nil)
