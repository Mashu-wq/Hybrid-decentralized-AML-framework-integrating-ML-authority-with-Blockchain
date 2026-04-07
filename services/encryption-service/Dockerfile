FROM golang:1.22-alpine AS builder
WORKDIR /build

# Copy Go workspace files (go.work ties the modules together)
COPY go.work go.work.sum ./

# Copy shared module source
COPY shared/go/ shared/go/

# Copy proto generated stubs
COPY proto/gen/go/ proto/gen/go/

# Copy encryption service source
COPY services/encryption-service/ services/encryption-service/

# Build the binary — CGO disabled for a fully static binary suitable for distroless
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o encryption-service \
    ./services/encryption-service/cmd/server/

# ---------------------------------------------------------------------------
# Runtime image — minimal distroless base (no shell, no package manager)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12

COPY --from=builder /build/encryption-service /encryption-service

# 50063 = gRPC
EXPOSE 50063

ENTRYPOINT ["/encryption-service"]
