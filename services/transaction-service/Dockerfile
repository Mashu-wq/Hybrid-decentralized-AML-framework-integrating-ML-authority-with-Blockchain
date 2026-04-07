# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /workspace

# Install build tools
RUN apk add --no-cache git ca-certificates tzdata

# Copy go workspace files (required for replace directives)
COPY go.work go.work.sum ./
COPY proto/gen/go/go.mod proto/gen/go/go.mod
COPY shared/go/go.mod shared/go/go.sum shared/go/

# Copy service and its dependencies
COPY services/transaction-service/go.mod services/transaction-service/go.sum ./services/transaction-service/
COPY proto/gen/go/ ./proto/gen/go/
COPY shared/go/ ./shared/go/
COPY services/transaction-service/ ./services/transaction-service/

WORKDIR /workspace/services/transaction-service

# Download dependencies
RUN go mod download

# Build binary with security hardening flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags=-static" \
    -trimpath \
    -o /bin/transaction-service \
    ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM scratch

# TLS certs and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /bin/transaction-service /bin/transaction-service

# Non-root user (numeric UID — scratch doesn't have /etc/passwd)
USER 65532:65532

EXPOSE 50062

ENTRYPOINT ["/bin/transaction-service"]
