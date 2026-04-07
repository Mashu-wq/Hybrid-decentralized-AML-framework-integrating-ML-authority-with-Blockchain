// Package metrics registers Prometheus metrics for the API Gateway and exposes
// a handler for the /metrics scrape endpoint.
package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// RequestsTotal counts every HTTP request that reaches the gateway.
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway",
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests handled by the API Gateway.",
	}, []string{"method", "path", "status"})

	// RequestDuration measures end-to-end request latency in seconds.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gateway",
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request duration in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path"})

	// RateLimitHits counts requests rejected by the rate limiter.
	RateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway",
		Name:      "rate_limit_hits_total",
		Help:      "Total number of requests rejected by the rate limiter.",
	}, []string{"client_type"}) // "public" or "service"

	// AuthCacheHits counts token-validation cache hits vs. misses.
	AuthCacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway",
		Name:      "auth_cache_total",
		Help:      "Token validation cache hits and misses.",
	}, []string{"result"}) // "hit" or "miss"

	// AuthDuration measures the time taken by IAM ValidateToken calls.
	AuthDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gateway",
		Name:      "auth_validation_duration_seconds",
		Help:      "Duration of IAM ValidateToken gRPC calls in seconds.",
		Buckets:   []float64{0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1},
	})

	// UpstreamErrors counts errors returned by upstream services.
	UpstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway",
		Name:      "upstream_errors_total",
		Help:      "Total number of upstream proxy errors.",
	}, []string{"service"})
)

// Handler returns the standard Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// StatusLabel converts an HTTP status code to a 3-digit string label.
func StatusLabel(code int) string {
	return strconv.Itoa(code)
}
