FROM golang:1.25-alpine AS builder
WORKDIR /build

# Copy Go workspace files (go.work ties the modules together)
COPY go.work go.work.sum ./

# Copy only the three workspace modules needed by the IAM service
COPY shared/go/            shared/go/
COPY proto/gen/go/         proto/gen/go/
COPY services/iam-service/ services/iam-service/

# Rewrite go.work to reference only the modules we copied.
# The original go.work lists all 11 services; go work sync would fail
# because the other 8 service directories are not in the build context.
RUN printf 'go 1.25.0\n\nuse (\n\t./services/iam-service\n\t./shared/go\n\t./proto/gen/go\n)\n' > go.work

# Download dependencies (cached as a separate layer)
RUN cd services/iam-service && go mod download

# Build the service binary — CGO disabled for a fully static binary suitable for distroless
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o iam-service \
    ./services/iam-service/cmd/server/

# Download grpc_health_probe — static binary used by Docker/K8s health checks
RUN PROBE_VER=v0.4.34 && \
    wget -qO /grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${PROBE_VER}/grpc_health_probe-linux-amd64" && \
    chmod +x /grpc_health_probe

# ---------------------------------------------------------------------------
# Runtime image — minimal distroless base (no shell, no package manager)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12

COPY --from=builder /build/iam-service    /iam-service
COPY --from=builder /grpc_health_probe    /grpc_health_probe

# 9000  = HTTP (health/metrics — reserved for future Prometheus endpoint)
# 50060 = gRPC
EXPOSE 9000 50060

ENTRYPOINT ["/iam-service"]
