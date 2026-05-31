// Package http provides a minimal REST/JSON server for the IAM service.
// It exposes the endpoints the API Gateway reverse-proxies:
//
//	POST /api/v1/auth/login
//	POST /api/v1/auth/register
//	POST /api/v1/auth/refresh
//	GET  /health
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fraud-detection/iam-service/internal/domain"
	"github.com/fraud-detection/iam-service/internal/service"
	"github.com/rs/zerolog"
)

// Server wraps the net/http server.
type Server struct {
	srv *http.Server
	log zerolog.Logger
}

// New constructs an HTTP Server and registers routes.
func New(authSvc *service.AuthService, log zerolog.Logger, port int) *Server {
	mux := http.NewServeMux()
	h := &handler{authSvc: authSvc, log: log}

	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.HandleFunc("POST /api/v1/auth/register", h.register)
	mux.HandleFunc("POST /api/v1/auth/refresh", h.refresh)
	mux.HandleFunc("GET /health", h.health)

	return &Server{
		log: log,
		srv: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.srv.Addr, err)
	}
	s.log.Info().Str("addr", s.srv.Addr).Msg("IAM HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

type handler struct {
	authSvc *service.AuthService
	log     zerolog.Logger
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// loginRequest is the JSON body for POST /api/v1/auth/login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code"`
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = strings.TrimPrefix(r.RemoteAddr, "[")
	}
	ua := r.UserAgent()

	result, err := h.authSvc.Login(r.Context(), req.Email, req.Password, req.MFACode, "", ip, ua)
	if err != nil {
		h.log.Error().Err(err).Str("email", req.Email).Msg("login error")
		writeAuthError(w, err)
		return
	}

	resp := map[string]interface{}{
		"access_token":       result.AccessToken,
		"refresh_token":      result.RefreshToken,
		"access_expires_in":  result.AccessExpiresIn,
		"refresh_expires_in": result.RefreshExpiresIn,
		"mfa_required":       result.MFARequired,
	}
	if result.MFARequired {
		resp["mfa_challenge_id"] = result.MFAChallengeID
	}
	if result.User != nil {
		resp["user_id"] = result.User.ID
		resp["email"] = result.User.Email
		resp["role"] = string(result.User.Role)
	}
	writeJSON(w, http.StatusOK, resp)
}

// registerRequest is the JSON body for POST /api/v1/auth/register.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if req.Role == "" {
		req.Role = "ANALYST"
	}

	// caller role from header (set by gateway after JWT validation)
	callerRole := r.Header.Get("X-User-Role")

	u, err := h.authSvc.Register(r.Context(), req.Email, req.Password, req.Role, callerRole)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user_id": u.ID,
		"email":   u.Email,
		"role":    string(u.Role),
	})
}

// refreshRequest is the JSON body for POST /api/v1/auth/refresh.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *handler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	result, err := h.authSvc.RefreshTokens(r.Context(), req.RefreshToken, "")
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":      result.AccessToken,
		"refresh_token":     result.NewRefreshToken,
		"access_expires_in": result.AccessExpiresIn,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeAuthError(w http.ResponseWriter, err error) {
	authErr, ok := err.(*domain.AuthError)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	status := http.StatusUnauthorized
	switch authErr.Code {
	case domain.ErrUserNotFound, domain.ErrInvalidCredentials:
		status = http.StatusUnauthorized
	case domain.ErrAccountLocked:
		status = http.StatusTooManyRequests
	case domain.ErrEmailTaken:
		status = http.StatusConflict
	case domain.ErrWeakPassword, domain.ErrPermissionDenied:
		status = http.StatusBadRequest
	}
	writeError(w, status, authErr.Message)
}
