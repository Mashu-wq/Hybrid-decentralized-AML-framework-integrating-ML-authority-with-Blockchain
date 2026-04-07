package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	iamv1 "github.com/fraud-detection/proto/gen/go/iam/v1"
	sharedmw "github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
)

// publicPaths are routes that do NOT require a JWT.
// Matched by prefix — order matters (more specific first).
var publicPaths = []string{
	"POST /api/v1/auth/login",
	"POST /api/v1/auth/register",
	"POST /api/v1/auth/refresh",
	"GET /health",
	"GET /metrics",
}

// cachedClaims holds the validated token claims until expiry.
type cachedClaims struct {
	userID      string
	email       string
	role        string
	permissions []string
	expiresAt   time.Time
}

// authCache stores validated token results keyed by SHA-256(token).
// This avoids hitting the IAM service on every request (target: <2 ms).
type authCache struct {
	mu      sync.RWMutex
	entries map[[32]byte]cachedClaims
	buffer  time.Duration // evict this far before actual expiry
}

func newAuthCache(buffer time.Duration) *authCache {
	c := &authCache{
		entries: make(map[[32]byte]cachedClaims),
		buffer:  buffer,
	}
	// Background eviction of expired entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			c.evict()
		}
	}()
	return c
}

func (c *authCache) key(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func (c *authCache) get(token string) (cachedClaims, bool) {
	k := c.key(token)
	c.mu.RLock()
	entry, ok := c.entries[k]
	c.mu.RUnlock()
	if !ok {
		return cachedClaims{}, false
	}
	if time.Now().Add(c.buffer).After(entry.expiresAt) {
		// Near or past expiry — treat as a cache miss.
		c.mu.Lock()
		delete(c.entries, k)
		c.mu.Unlock()
		return cachedClaims{}, false
	}
	return entry, true
}

func (c *authCache) set(token string, claims cachedClaims) {
	k := c.key(token)
	c.mu.Lock()
	c.entries[k] = claims
	c.mu.Unlock()
}

func (c *authCache) evict() {
	deadline := time.Now()
	c.mu.Lock()
	for k, v := range c.entries {
		if deadline.After(v.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// Auth validates the JWT Bearer token on every non-public request.
// Valid tokens are cached to minimise round-trips to the IAM service.
func Auth(iamClient iamv1.IAMServiceClient, cacheBuffer time.Duration, log zerolog.Logger) Func {
	cache := newAuthCache(cacheBuffer)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicPath(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			token, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}

			claims, ok := cache.get(token)
			if !ok {
				// Call IAM service to validate.
				resp, err := iamClient.ValidateToken(r.Context(), &iamv1.ValidateTokenRequest{
					AccessToken: token,
				})
				if err != nil || !resp.Valid {
					code := "TOKEN_INVALID"
					if resp != nil && resp.ErrorCode != "" {
						code = resp.ErrorCode
					}
					log.Warn().
						Str("path", r.URL.Path).
						Str("error_code", code).
						Msg("token validation failed")
					writeAuthError(w, http.StatusUnauthorized, "invalid or expired token")
					return
				}

				claims = cachedClaims{
					userID:      resp.UserId,
					email:       resp.Email,
					role:        resp.Role,
					permissions: resp.Permissions,
					expiresAt:   resp.ExpiresAt,
				}
				cache.set(token, claims)
			}

			// Inject identity into context (readable by proxy and logging).
			ctx := context.WithValue(r.Context(), sharedmw.CtxUserID, claims.userID)
			ctx = context.WithValue(ctx, sharedmw.CtxUserRole, claims.role)

			// Forward identity headers to downstream services.
			r.Header.Set("X-User-ID", claims.userID)
			r.Header.Set("X-User-Role", claims.role)
			r.Header.Set("X-User-Email", claims.email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isPublicPath reports whether the combination of HTTP method and URL path
// matches a public (unauthenticated) route.
func isPublicPath(method, path string) bool {
	// OPTIONS is always public (CORS preflight).
	if method == http.MethodOptions {
		return true
	}
	for _, entry := range publicPaths {
		parts := strings.SplitN(entry, " ", 2)
		if len(parts) != 2 {
			continue
		}
		m, p := parts[0], parts[1]
		if strings.EqualFold(m, method) && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func extractBearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("no Authorization header")
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return "", fmt.Errorf("Authorization header is not Bearer")
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		return "", fmt.Errorf("empty Bearer token")
	}
	return token, nil
}

type errBody struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: msg, Code: status})
}
