// Package http (server.go) configures routing and starts the HTTP server.
package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Server is the HTTP server for the Case Management REST API.
type Server struct {
	srv *http.Server
}

// NewServer builds the HTTP mux and returns a Server ready to run.
//
// Route table:
//
//	GET    /health                            → HealthCheck
//	GET    /cases                             → ListCases
//	POST   /cases                             → CreateCase
//	GET    /cases/stats                       → GetCaseStats
//	GET    /cases/workload                    → GetWorkload
//	GET    /cases/:id                         → GetCase
//	PATCH  /cases/:id/status                  → UpdateCaseStatus
//	POST   /cases/:id/assign                  → AssignCase
//	POST   /cases/:id/sar                     → GenerateSAR
//	POST   /cases/:id/evidence                → AddEvidence
//	GET    /cases/:id/evidence                → GetEvidence
//	DELETE /cases/:id/evidence/:evidence_id   → DeleteEvidence
func NewServer(h *Handler, port int) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", h.HealthCheck)

	// Fixed routes (must come before the catch-all)
	mux.HandleFunc("/cases/stats", methodGuard(http.MethodGet, h.GetCaseStats))
	mux.HandleFunc("/cases/workload", methodGuard(http.MethodGet, h.GetWorkload))

	// /cases — list + create
	mux.HandleFunc("/cases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.ListCases(w, r)
		case http.MethodPost:
			h.CreateCase(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /cases/* sub-router
	mux.HandleFunc("/cases/", caseRouter(h))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return &Server{srv: srv}
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	log.Info().Str("addr", s.srv.Addr).Msg("case-service HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http serve: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Case sub-router — dispatches /cases/{id}/* paths
// ---------------------------------------------------------------------------

func caseRouter(h *Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// PATCH /cases/:id/status
		case strings.HasSuffix(path, "/status") && r.Method == http.MethodPatch:
			h.UpdateCaseStatus(w, r)

		// POST /cases/:id/assign
		case strings.HasSuffix(path, "/assign") && r.Method == http.MethodPost:
			h.AssignCase(w, r)

		// POST /cases/:id/sar
		case strings.HasSuffix(path, "/sar") && r.Method == http.MethodPost:
			h.GenerateSAR(w, r)

		// /cases/:id/evidence[/:evidence_id]
		case strings.Contains(path, "/evidence"):
			switch r.Method {
			case http.MethodPost:
				h.AddEvidence(w, r)
			case http.MethodGet:
				h.GetEvidence(w, r)
			case http.MethodDelete:
				h.DeleteEvidence(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}

		// GET /cases/:id
		case r.Method == http.MethodGet:
			h.GetCase(w, r)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

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
