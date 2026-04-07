// Package health provides the /health aggregation endpoint.
// It concurrently checks the /health endpoint of every downstream service and
// aggregates the results into a single JSON response.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	checkTimeout  = 5 * time.Second
	statusHealthy = "healthy"
	statusDegraded = "degraded"
	statusUnhealthy = "unhealthy"
)

// ServiceStatus holds the result for a single downstream service.
type ServiceStatus struct {
	Status  string `json:"status"`
	Latency string `json:"latency_ms,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Response is the JSON body returned by GET /health.
type Response struct {
	Status    string                   `json:"status"`
	Timestamp string                   `json:"timestamp"`
	Services  map[string]ServiceStatus `json:"services"`
}

// ServiceAddrs maps a human-readable name to the HTTP base URL of the service.
type ServiceAddrs map[string]string

// Handler returns an http.HandlerFunc that aggregates downstream health checks.
func Handler(services ServiceAddrs) http.HandlerFunc {
	client := &http.Client{Timeout: checkTimeout}

	return func(w http.ResponseWriter, r *http.Request) {
		results := make(map[string]ServiceStatus, len(services))
		var mu sync.Mutex
		var wg sync.WaitGroup

		for name, baseURL := range services {
			wg.Add(1)
			go func(svcName, url string) {
				defer wg.Done()
				st := checkService(r.Context(), client, url+"/health")
				mu.Lock()
				results[svcName] = st
				mu.Unlock()
			}(name, baseURL)
		}
		wg.Wait()

		overall := aggregate(results)
		resp := Response{
			Status:    overall,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Services:  results,
		}

		statusCode := http.StatusOK
		if overall == statusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// checkService performs a single health check HTTP GET and returns the result.
func checkService(ctx context.Context, client *http.Client, healthURL string) ServiceStatus {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return ServiceStatus{Status: statusUnhealthy, Error: err.Error()}
	}

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	latencyStr := latencyString(latency)

	if err != nil {
		return ServiceStatus{Status: statusUnhealthy, Latency: latencyStr, Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return ServiceStatus{Status: statusHealthy, Latency: latencyStr}
	}
	return ServiceStatus{
		Status:  statusDegraded,
		Latency: latencyStr,
		Error:   http.StatusText(resp.StatusCode),
	}
}

// aggregate determines the overall status from individual results.
// healthy  → all services are healthy
// degraded → at least one service is degraded but none are unhealthy
// unhealthy → at least one service is unhealthy
func aggregate(results map[string]ServiceStatus) string {
	overall := statusHealthy
	for _, s := range results {
		switch s.Status {
		case statusUnhealthy:
			return statusUnhealthy
		case statusDegraded:
			overall = statusDegraded
		}
	}
	return overall
}

func latencyString(ms int64) string {
	return fmt.Sprintf("%dms", ms)
}
