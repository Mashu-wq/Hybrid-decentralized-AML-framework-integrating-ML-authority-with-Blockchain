FROM golang:1.25-alpine AS builder
WORKDIR /build

# Copy Go workspace files (go.work ties the modules together)
COPY go.work go.work.sum ./

# Copy shared module source
COPY shared/go/ shared/go/

# Copy proto generated stubs
COPY proto/gen/go/ proto/gen/go/

# Copy encryption service source
COPY services/encryption-service/ services/encryption-service/

# Rewrite go.work to reference only the modules we copied.
RUN printf 'go 1.25.0\n\nuse (\n\t./services/encryption-service\n\t./shared/go\n\t./proto/gen/go\n)\n' > go.work

# Download dependencies (cached as a separate layer)
RUN cd services/encryption-service && go mod download

# Build the binary — CGO disabled for a fully static binary suitable for distroless
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o encryption-service \
    ./services/encryption-service/cmd/server/

# Download grpc_health_probe — static binary used by Docker/K8s health checks
RUN PROBE_VER=v0.4.34 && \
    wget -qO /grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${PROBE_VER}/grpc_health_probe-linux-amd64" && \
    chmod +x /grpc_health_probe

# ---------------------------------------------------------------------------
# Runtime image — minimal distroless base (no shell, no package manager)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12

COPY --from=builder /build/encryption-service /encryption-service
COPY --from=builder /grpc_health_probe        /grpc_health_probe

# 50066 = gRPC
EXPOSE 50066

ENTRYPOINT ["/encryption-service"]
