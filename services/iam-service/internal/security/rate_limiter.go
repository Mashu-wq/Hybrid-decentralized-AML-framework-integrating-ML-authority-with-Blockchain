// internal/security/rate_limiter.go
package security

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
	}
}

func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}
	
	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *RateLimiter) cleanupVisitors() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	for ip, v := range rl.visitors {
		if time.Since(v.lastSeen) > 5*time.Minute {
			delete(rl.visitors, ip)
		}
	}
}

func RateLimitMiddleware(rps int, burst int) gin.HandlerFunc {
	limiter := NewRateLimiter(rate.Limit(rps), burst)
	
	// Start cleanup goroutine
	go func() {
		for {
			time.Sleep(time.Minute)
			limiter.cleanupVisitors()
		}
	}()
	
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := limiter.getVisitor(ip)
		
		if !limiter.Allow() {
			c.JSON(429, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}