# =============================================================================
# API Gateway — multi-stage Docker build
# Stage 1: compile the gateway binary inside the Go workspace
# Stage 2: minimal runtime image
# =============================================================================

# --- Builder -----------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /workspace

RUN apk add --no-cache git

# Copy only the modules this service depends on.
COPY go.work go.work.sum* ./
COPY shared/go/        shared/go/
COPY proto/gen/go/     proto/gen/go/
COPY services/api-gateway/ services/api-gateway/

# Replace the workspace file with a minimal one that only references
# the three modules present in this build context.
RUN printf 'go 1.25.0\n\nuse (\n\t./services/api-gateway\n\t./shared/go\n\t./proto/gen/go\n)\n' > go.work

RUN cd services/api-gateway && go mod download

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
