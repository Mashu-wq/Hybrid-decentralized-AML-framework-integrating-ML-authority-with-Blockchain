// Package middleware provides the HTTP middleware chain for the API Gateway.
package middleware

import "net/http"

// captureWriter wraps http.ResponseWriter to intercept the status code written
// by the handler so that middleware (logging, tracing) can read it after the
// fact.
type captureWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (cw *captureWriter) WriteHeader(code int) {
	if !cw.written {
		cw.statusCode = code
		cw.written = true
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	if !cw.written {
		cw.statusCode = http.StatusOK
		cw.written = true
	}
	return cw.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter for middleware that need it
// (e.g. http.Flusher, http.Hijacker).
func (cw *captureWriter) Unwrap() http.ResponseWriter {
	return cw.ResponseWriter
}

// newCaptureWriter wraps w with status-code capture, defaulting to 200.
func newCaptureWriter(w http.ResponseWriter) *captureWriter {
	return &captureWriter{ResponseWriter: w, statusCode: http.StatusOK}
}
