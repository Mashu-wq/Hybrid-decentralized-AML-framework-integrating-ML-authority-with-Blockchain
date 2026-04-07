# ============================================================================
# Stage 1 — builder
# ============================================================================
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /workspace

# Copy workspace files so go.work replace directives resolve
COPY go.work go.work.sum ./
COPY proto/gen/go/ proto/gen/go/
COPY shared/go/ shared/go/
COPY services/case-service/ services/case-service/

WORKDIR /workspace/services/case-service

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /case-service ./cmd/server

# ============================================================================
# Stage 2 — minimal runtime image
# ============================================================================
FROM scratch

# TLS root certificates for HTTPS calls (S3, Blockchain Service)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Non-root user: UID/GID 65532 (distroless convention)
COPY --from=builder /etc/passwd /etc/passwd
USER 65532:65532

COPY --from=builder /case-service /case-service

# REST API
EXPOSE 9004
# gRPC
EXPOSE 10004

ENTRYPOINT ["/case-service"]
