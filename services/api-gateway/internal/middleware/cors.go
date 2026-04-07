package middleware

import (
	"net/http"
	"strings"
)

const (
	corsMaxAge       = "86400"
	corsAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type, X-Request-ID, X-API-Key, X-Caller-Service"
	corsExposeHeaders = "X-Request-ID, X-Trace-ID, X-RateLimit-Limit, Retry-After"
)

// CORS applies Cross-Origin Resource Sharing headers using the provided origin
// whitelist.  OPTIONS preflight requests are terminated early (200 OK) so they
// do not pass through the authentication or rate-limiting middleware.
func CORS(allowedOrigins []string) Func {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[strings.ToLower(o)] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && isAllowedOrigin(origin, originSet) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}

			w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", corsMaxAge)

			// Preflight: stop here with 200 OK.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isAllowedOrigin(origin string, set map[string]struct{}) bool {
	_, ok := set[strings.ToLower(origin)]
	return ok
}
