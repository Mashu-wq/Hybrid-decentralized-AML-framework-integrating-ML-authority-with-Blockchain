FROM golang:1.22-alpine AS builder
WORKDIR /build

# Copy Go workspace files (go.work ties the modules together)
COPY go.work go.work.sum ./

# Copy shared module source
COPY shared/go/ shared/go/

# Copy IAM service source
COPY services/iam-service/ services/iam-service/

# Build the binary — CGO disabled for a fully static binary suitable for distroless
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o iam-service \
    ./services/iam-service/cmd/server/

# ---------------------------------------------------------------------------
# Runtime image — minimal distroless base (no shell, no package manager)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12

COPY --from=builder /build/iam-service /iam-service

# 9000  = HTTP (health/metrics)
# 50060 = gRPC
EXPOSE 9000 50060

ENTRYPOINT ["/iam-service"]
