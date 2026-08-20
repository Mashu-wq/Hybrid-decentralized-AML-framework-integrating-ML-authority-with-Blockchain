package grpcclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/connectivity"
)

// freeAddr returns an address that nothing is listening on (the listener is
// opened to reserve the port, then closed) so a dial to it cannot connect.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestNonBlockingDialReturnsUsableConnWhenServerDown is the regression test for
// the transaction-service "ML reconnect" bug: a non-blocking dial to an
// unavailable server must return a non-nil, usable ClientConn immediately
// (rather than erroring), so the caller never permanently loses the client.
// The ClientConn connects lazily and reconnects on its own once the server is up.
func TestNonBlockingDialReturnsUsableConnWhenServerDown(t *testing.T) {
	addr := freeAddr(t)

	start := time.Now()
	conn, err := New(context.Background(), Config{
		Target:        addr,
		CallerService: "test",
		NonBlocking:   true,
		Log:           zerolog.Nop(),
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("non-blocking dial to down server should not error, got: %v", err)
	}
	if conn == nil {
		t.Fatal("non-blocking dial must return a non-nil ClientConn")
	}
	defer conn.Close()

	// Must return promptly without waiting on any connect timeout.
	if elapsed > 2*time.Second {
		t.Fatalf("non-blocking dial took too long (%s); it should return immediately", elapsed)
	}

	// The conn is in IDLE (or CONNECTING) — usable, not shut down.
	if s := conn.GetState(); s == connectivity.Shutdown {
		t.Fatalf("expected a live ClientConn, got state %s", s)
	}
}

// TestBlockingDialErrorsWhenServerDown documents the default (blocking)
// behavior: it waits up to DialTimeout and then errors when the server is
// unreachable. This is the behavior that made the ML client nil at startup;
// dependencies that must fail open use NonBlocking instead.
func TestBlockingDialErrorsWhenServerDown(t *testing.T) {
	addr := freeAddr(t)

	_, err := New(context.Background(), Config{
		Target:        addr,
		CallerService: "test",
		DialTimeout:   500 * time.Millisecond,
		Log:           zerolog.Nop(),
	})
	if err == nil {
		t.Fatal("blocking dial to a down server should error within DialTimeout")
	}
}
