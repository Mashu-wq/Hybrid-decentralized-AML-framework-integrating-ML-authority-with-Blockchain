# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /workspace

RUN apk add --no-cache git ca-certificates tzdata

COPY go.work go.work.sum ./
COPY proto/gen/go/ proto/gen/go/
COPY shared/go/ shared/go/
COPY services/blockchain-service/ services/blockchain-service/

RUN printf 'go 1.25.0\n\nuse (\n\t./services/blockchain-service\n\t./shared/go\n\t./proto/gen/go\n)\n' > go.work

WORKDIR /workspace/services/blockchain-service

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -trimpath \
    -o /bin/blockchain-service \
    ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

# wget for health checks; ca-certificates and tzdata for TLS and time zones
RUN apk add --no-cache ca-certificates tzdata wget

RUN addgroup -S blockchain && adduser -S blockchain -G blockchain

COPY --from=builder /bin/blockchain-service /bin/blockchain-service

USER blockchain

# HTTP REST port (used by kyc-service, case-service, and the internal API)
EXPOSE 9005

ENTRYPOINT ["/bin/blockchain-service"]
