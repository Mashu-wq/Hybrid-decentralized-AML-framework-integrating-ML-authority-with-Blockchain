## Multi-stage build for the KYC service.
## Stage 1 compiles the binary; Stage 2 produces a minimal runtime image.
## This pattern matches the other services in this repository.

# ---- Builder ----
FROM golang:1.22-alpine AS builder

# Install build dependencies.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy workspace files first so module graph is resolved correctly.
COPY go.work go.work.sum ./

# Copy shared libraries and proto stubs.
COPY shared/go/ shared/go/
COPY proto/gen/go/ proto/gen/go/

# Copy service source.
COPY services/kyc-service/ services/kyc-service/

# Build the binary.
RUN cd services/kyc-service && \
    CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -extldflags '-static'" \
        -o /kyc-service \
        ./cmd/server/

# ---- Runtime ----
FROM alpine:3.19

# ca-certificates: required for TLS to upstream services (Vault, Jaeger, etc.).
# tzdata: required for time zone handling in Go.
RUN apk add --no-cache ca-certificates tzdata

# Run as non-root user.
RUN addgroup -S kyc && adduser -S kyc -G kyc

COPY --from=builder /kyc-service /kyc-service

USER kyc

# Expose HTTP and gRPC ports.
EXPOSE 9001 50061

ENTRYPOINT ["/kyc-service"]
