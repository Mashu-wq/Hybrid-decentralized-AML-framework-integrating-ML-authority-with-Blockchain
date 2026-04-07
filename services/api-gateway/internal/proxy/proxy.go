// Package proxy implements the reverse-proxy routing layer.
// Each downstream service gets its own httputil.ReverseProxy instance so that
// connection pools are isolated and error handling is per-service.
package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// route pairs a URL path prefix with the upstream base URL.
type route struct {
	prefix   string
	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// Router dispatches requests to downstream services based on the URL prefix.
// Path: /api/v1/<service>/... → http://<service-host>:<port>/api/v1/<service>/...
// The full path is forwarded unchanged; each service already registers its
// own /api/v1/<service>/... routes.
type Router struct {
	routes []route
	log    zerolog.Logger
}

// ServiceAddrs maps service names to their HTTP base URLs.
type ServiceAddrs struct {
	IAM         string
	KYC         string
	Transaction string
	Alert       string
	Case        string
	Analytics   string
	Blockchain  string
}

// New constructs a Router from the provided service address map.
func New(addrs ServiceAddrs, log zerolog.Logger) (*Router, error) {
	entries := []struct {
		prefix string
		addr   string
	}{
		{"/api/v1/auth/", addrs.IAM},
		{"/api/v1/users/", addrs.IAM},
		{"/api/v1/kyc/", addrs.KYC},
		{"/api/v1/transactions/", addrs.Transaction},
		{"/api/v1/alerts/", addrs.Alert},
		{"/api/v1/cases/", addrs.Case},
		{"/api/v1/analytics/", addrs.Analytics},
		{"/api/v1/blockchain/", addrs.Blockchain},
	}

	r := &Router{log: log}
	for _, e := range entries {
		u, err := url.Parse(e.addr)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL %q for prefix %q: %w", e.addr, e.prefix, err)
		}
		rp := newReverseProxy(u, log)
		r.routes = append(r.routes, route{prefix: e.prefix, upstream: u, proxy: rp})
	}
	return r, nil
}

// ServeHTTP implements http.Handler — match the request to a route and proxy it.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for _, rt := range r.routes {
		if strings.HasPrefix(req.URL.Path, rt.prefix) {
			rt.proxy.ServeHTTP(w, req)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": fmt.Sprintf("no route for %s %s", req.Method, req.URL.Path),
		"code":  http.StatusNotFound,
	})
}

// newReverseProxy builds an httputil.ReverseProxy for the given upstream.
func newReverseProxy(upstream *url.URL, log zerolog.Logger) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(upstream)

	// Custom transport with reasonable timeouts.
	rp.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// Rewrite the request before forwarding.
	rp.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		// Preserve the full path; do not add upstream.Path prefix since it's
		// empty (base URL has no path component).
		req.Host = upstream.Host

		// Strip the Authorization header so downstream services do not
		// receive the raw JWT — identity is already injected as X-User-* headers.
		req.Header.Del("Authorization")
	}

	// Handle upstream errors gracefully.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error().
			Err(err).
			Str("upstream", upstream.Host).
			Str("path", r.URL.Path).
			Msg("upstream error")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "upstream service unavailable",
			"code":  http.StatusBadGateway,
		})
	}

	return rp
}
