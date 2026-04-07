# =============================================================================
# API Gateway — multi-stage Docker build
# Stage 1: compile the gateway binary inside the Go workspace
# Stage 2: minimal runtime image
# =============================================================================

# --- Builder -----------------------------------------------------------------
FROM golang:1.23-alpine AS builder

WORKDIR /workspace

RUN apk add --no-cache git

# Copy the entire Go workspace so module replacements resolve correctly.
COPY go.work go.work.sum* ./
COPY shared/           shared/
COPY proto/gen/go/     proto/gen/go/
COPY services/api-gateway/ services/api-gateway/

# Download dependencies declared by the workspace.
RUN go work sync

# Build a statically linked binary (no CGO).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-s -w" \
      -o /out/api-gateway \
      ./services/api-gateway/cmd/server

# --- Runtime -----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/api-gateway /api-gateway

# The gateway listens on 8080 by default (API_GATEWAY_PORT).
EXPOSE 8080

ENTRYPOINT ["/api-gateway"]
