// Package http provides the HTTP/REST server for the KYC service.
// Routes are registered using Go 1.22's enhanced ServeMux with method-pattern syntax.
package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/fraud-detection/kyc-service/internal/service"
	"github.com/fraud-detection/kyc-service/internal/storage"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Server wraps the HTTP server and its handler.
type Server struct {
	handler http.Handler
	srv     *http.Server
	log     zerolog.Logger
}

// New constructs an HTTP Server with all routes registered.
func New(kycSvc *service.KYCService, store storage.DocumentStore, log zerolog.Logger, port int) *Server {
	s := &Server{log: log}

	mux := http.NewServeMux()
	h := NewKYCHTTPHandler(kycSvc, store, log)

	// Register routes using Go 1.22 enhanced mux (method + path patterns).
	// Customer lifecycle
	mux.HandleFunc("POST /api/v1/kyc/customers", h.RegisterCustomer)
	mux.HandleFunc("GET /api/v1/kyc/customers", h.ListCustomers)
	mux.HandleFunc("GET /api/v1/kyc/customers/{id}", h.GetKYCRecord)
	mux.HandleFunc("PATCH /api/v1/kyc/customers/{id}/status", h.UpdateKYCStatus)

	// Document and biometrics
	mux.HandleFunc("POST /api/v1/kyc/customers/{id}/documents", h.SubmitDocument)
	mux.HandleFunc("POST /api/v1/kyc/customers/{id}/face-verify", h.VerifyFace)

	// PII access (privileged)
	mux.HandleFunc("GET /api/v1/kyc/customers/{id}/pii", h.GetDecryptedPII)

	// Health
	mux.HandleFunc("GET /health", h.HealthCheck)

	// Wrap with shared middleware.
	s.handler = chain(mux,
		requestIDMiddleware,
		jsonContentTypeMiddleware,
		loggingMiddleware(log),
	)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// Run starts the HTTP server and blocks until ctx is cancelled.
// On cancellation, a graceful shutdown is attempted.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info().Str("addr", s.srv.Addr).Msg("KYC HTTP server listening")
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http listen and serve: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.log.Info().Msg("context cancelled — stopping HTTP server gracefully")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("http graceful shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// middlewareFunc is the type for handler-wrapping middleware.
type middlewareFunc func(http.Handler) http.Handler

// chain applies middleware in left-to-right order (outermost first).
func chain(h http.Handler, middleware ...middlewareFunc) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// requestIDMiddleware injects a unique request ID into the request context
// and sets it as the X-Request-ID response header.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jsonContentTypeMiddleware sets Content-Type: application/json on all responses.
func jsonContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs every HTTP request with method, path, status, and duration.
func loggingMiddleware(log zerolog.Logger) middlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rw, r)

			reqID, _ := r.Context().Value(ctxKeyRequestID{}).(string)
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", rw.statusCode).
				Dur("duration_ms", time.Since(start)).
				Str("request_id", reqID).
				Str("remote_addr", r.RemoteAddr).
				Msg("HTTP request")
		})
	}
}

// ---------------------------------------------------------------------------
// Context keys and response writer wrapper
// ---------------------------------------------------------------------------

// ctxKeyRequestID is the context key for the HTTP request ID.
type ctxKeyRequestID struct{}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
