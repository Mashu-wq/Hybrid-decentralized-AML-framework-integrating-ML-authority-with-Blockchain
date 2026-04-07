package middleware

import (
	"context"
	"net/http"

	sharedmw "github.com/fraud-detection/shared/middleware"
	"github.com/google/uuid"
)

// RequestID ensures every request has a unique X-Request-ID.
// If the client supplies the header, it is reused verbatim.
// The ID is stored in the request context under the shared middleware key so
// that outgoing gRPC calls (via the shared client interceptors) can propagate it.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), sharedmw.CtxRequestID, reqID)

		// Echo back on every response so clients can correlate logs.
		w.Header().Set("X-Request-ID", reqID)

		// Also set on the request so upstream service proxies see it.
		r.Header.Set("X-Request-ID", reqID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
