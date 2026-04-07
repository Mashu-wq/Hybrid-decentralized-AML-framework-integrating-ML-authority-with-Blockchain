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
COPY services/alert-service/ services/alert-service/

WORKDIR /workspace/services/alert-service

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /alert-service ./cmd/server

# ============================================================================
# Stage 2 — minimal runtime image
# ============================================================================
FROM scratch

# TLS root certificates for HTTPS calls (SendGrid, Twilio, Slack)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Non-root user: UID/GID 65532 (distroless convention)
COPY --from=builder /etc/passwd /etc/passwd
USER 65532:65532

COPY --from=builder /alert-service /alert-service

# REST API + WebSocket
EXPOSE 9003
# gRPC
EXPOSE 10003

ENTRYPOINT ["/alert-service"]
