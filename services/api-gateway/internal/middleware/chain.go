package middleware

import "net/http"

// Func is an HTTP handler-wrapping middleware function.
type Func func(http.Handler) http.Handler

// Chain applies middleware in left-to-right order so that the first entry
// is outermost — it runs first on the inbound path and last on the outbound path.
//
// Example execution order for Chain(h, A, B, C):
//
//	request  → A → B → C → handler
//	response ← A ← B ← C ← handler
func Chain(h http.Handler, mw ...Func) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
