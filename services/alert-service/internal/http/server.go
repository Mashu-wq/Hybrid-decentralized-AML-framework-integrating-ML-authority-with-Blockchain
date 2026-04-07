// Package http (server.go) configures routing and starts the HTTP server.
package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	ws "github.com/fraud-detection/alert-service/internal/websocket"
	"github.com/rs/zerolog/log"
)

// Server is the HTTP server for the REST API and WebSocket upgrade endpoint.
type Server struct {
	srv *http.Server
	hub *ws.Hub
}

// NewServer builds the HTTP mux, wires all routes, and returns a Server.
//
// Route table:
//
//	GET  /health                       → HealthCheck
//	GET  /ws                           → WebSocket upgrade
//	GET  /alerts                       → ListAlerts
//	GET  /alerts/stats                 → GetAlertStats
//	GET  /alerts/customer/{id}         → GetAlertsByCustomer
//	GET  /alerts/{id}                  → GetAlert
//	PATCH /alerts/{id}/status          → UpdateAlertStatus
//	POST  /alerts/{id}/assign          → AssignAlert
//	POST  /alerts/{id}/escalate        → EscalateAlert
func NewServer(h *Handler, hub *ws.Hub, port int) *Server {
	mux := http.NewServeMux()

	// Observability
	mux.HandleFunc("/health", h.HealthCheck)

	// WebSocket
	mux.HandleFunc("/ws", hub.ServeWS)

	// Alert endpoints — dispatched manually because Go 1.23 stdlib mux
	// does not support path parameters; we parse them in the handler.
	mux.HandleFunc("/alerts/stats", methodGuard(http.MethodGet, h.GetAlertStats))
	mux.HandleFunc("/alerts/customer/", methodGuard(http.MethodGet, h.GetAlertsByCustomer))
	mux.HandleFunc("/alerts/", alertRouter(h))
	mux.HandleFunc("/alerts", methodGuard(http.MethodGet, h.ListAlerts))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{srv: srv, hub: hub}
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	log.Info().Str("addr", s.srv.Addr).Msg("HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http serve: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("context cancelled — shutting down HTTP server")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Alert sub-router — dispatches /alerts/{id}/* paths
// ---------------------------------------------------------------------------

func alertRouter(h *Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/status") && r.Method == http.MethodPatch:
			h.UpdateAlertStatus(w, r)
		case strings.HasSuffix(path, "/assign") && r.Method == http.MethodPost:
			h.AssignAlert(w, r)
		case strings.HasSuffix(path, "/escalate") && r.Method == http.MethodPost:
			h.EscalateAlert(w, r)
		case r.Method == http.MethodGet:
			h.GetAlert(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ---------------------------------------------------------------------------
// Middleware helpers
// ---------------------------------------------------------------------------

func methodGuard(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", rw.code).
			Dur("latency_ms", time.Since(start)).
			Msg("http")
	})
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}
