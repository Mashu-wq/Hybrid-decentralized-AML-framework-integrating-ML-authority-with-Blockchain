package middleware

import (
	"net/http"
	"time"

	"github.com/fraud-detection/shared/logger"
	sharedmw "github.com/fraud-detection/shared/middleware"
	"github.com/fraud-detection/shared/tracing"
)

// Logging logs every HTTP request with structured fields after the response is
// written.  It captures the status code from captureWriter so that even
// middleware-level rejections (401, 429) are reflected correctly.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		cw := newCaptureWriter(w)

		next.ServeHTTP(cw, r)

		// Pull correlation IDs from the request context (set by earlier middleware).
		ctx := r.Context()
		reqID, _ := ctx.Value(sharedmw.CtxRequestID).(string)
		userID, _ := ctx.Value(sharedmw.CtxUserID).(string)

		log := logger.FromContext(ctx)
		evt := log.Info()
		if cw.statusCode >= 500 {
			evt = log.Error()
		} else if cw.statusCode >= 400 {
			evt = log.Warn()
		}

		evt.
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("query", r.URL.RawQuery).
			Int("status", cw.statusCode).
			Dur("duration_ms", time.Since(start)).
			Str("request_id", reqID).
			Str("user_id", userID).
			Str("trace_id", tracing.TraceID(ctx)).
			Str("remote_addr", clientIP(r)).
			Str("user_agent", r.UserAgent()).
			Msg("http request")
	})
}
