package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucket is a single token-bucket for one client.
type bucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64   // == RPM (max burst)
	rate     float64   // tokens per second (RPM / 60)
	lastFill time.Time
	lastSeen time.Time
}

func newBucket(rpm int) *bucket {
	cap := float64(rpm)
	return &bucket{
		tokens:   cap,
		capacity: cap,
		rate:     cap / 60.0,
		lastFill: time.Now(),
		lastSeen: time.Now(),
	}
}

// allow refills the bucket and returns true if there is a token to consume.
func (b *bucket) allow() bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastFill = now
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// retryAfterSeconds returns the seconds until one token is available.
func (b *bucket) retryAfterSeconds() int {
	b.mu.Lock()
	deficit := 1.0 - b.tokens
	b.mu.Unlock()
	if deficit <= 0 {
		return 0
	}
	secs := int(deficit/b.rate) + 1
	return secs
}

// rateLimiter manages buckets for multiple clients.
type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	publicRPM  int
	serviceRPM int
}

func newRateLimiter(publicRPM, serviceRPM int) *rateLimiter {
	rl := &rateLimiter{
		buckets:    make(map[string]*bucket),
		publicRPM:  publicRPM,
		serviceRPM: serviceRPM,
	}
	// Evict buckets idle for more than 10 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.evict(10 * time.Minute)
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(r *http.Request) (ok bool, retryAfter int) {
	clientKey, rpm := rl.identify(r)

	rl.mu.Lock()
	b, exists := rl.buckets[clientKey]
	if !exists {
		b = newBucket(rpm)
		rl.buckets[clientKey] = b
	}
	rl.mu.Unlock()

	if b.allow() {
		return true, 0
	}
	return false, b.retryAfterSeconds()
}

// identify returns a stable client key and the applicable RPM limit.
func (rl *rateLimiter) identify(r *http.Request) (string, int) {
	// Service-to-service: presence of X-Caller-Service header.
	if svc := r.Header.Get("X-Caller-Service"); svc != "" {
		return fmt.Sprintf("svc:%s", svc), rl.serviceRPM
	}
	// API key header.
	if key := r.Header.Get("X-API-Key"); key != "" {
		return fmt.Sprintf("apikey:%s", key), rl.publicRPM
	}
	// Fall back to the client IP.
	ip := clientIP(r)
	return fmt.Sprintf("ip:%s", ip), rl.publicRPM
}

func (rl *rateLimiter) evict(idleFor time.Duration) {
	cutoff := time.Now().Add(-idleFor)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, b := range rl.buckets {
		b.mu.Lock()
		seen := b.lastSeen
		b.mu.Unlock()
		if seen.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

// RateLimit enforces a token-bucket rate limit per client.
// Public clients: publicRPM. Service-to-service (X-Caller-Service present): serviceRPM.
func RateLimit(publicRPM, serviceRPM int) Func {
	rl := newRateLimiter(publicRPM, serviceRPM)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// OPTIONS preflight is never rate-limited.
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			ok, retryAfter := rl.allow(r)
			if !ok {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.publicRPM))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(errBody{
					Error: "rate limit exceeded",
					Code:  http.StatusTooManyRequests,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the real client IP, honouring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the chain is the originating client.
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
