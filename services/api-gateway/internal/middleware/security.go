package middleware

import "net/http"

// Security sets defensive HTTP response headers on every response.
// Headers follow OWASP recommendations and are safe for REST API responses.
func Security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Prevent browsers from MIME-sniffing the response type.
		h.Set("X-Content-Type-Options", "nosniff")

		// Deny framing to prevent clickjacking.
		h.Set("X-Frame-Options", "DENY")

		// Legacy XSS filter (belt-and-suspenders for older browsers).
		h.Set("X-XSS-Protection", "1; mode=block")

		// Enforce HTTPS for 1 year (including subdomains) in production.
		// Browsers will ignore this over plain HTTP, so it only takes effect
		// once the first HTTPS response is seen.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Restrict how much referrer info is sent cross-origin.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Disable browser features that this API surface never needs.
		h.Set("Permissions-Policy",
			"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
				"magnetometer=(), microphone=(), payment=(), usb=()")

		// Content-Security-Policy for JSON API responses.
		// Disallows any browser rendering of the response as HTML.
		h.Set("Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'")

		// Prevent caching of sensitive API responses by default.
		// Individual handlers may override this for public/cacheable data.
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
