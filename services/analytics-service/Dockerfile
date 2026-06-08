# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /workspace

RUN apk add --no-cache git ca-certificates tzdata

COPY go.work go.work.sum ./
COPY proto/gen/go/ proto/gen/go/
COPY shared/go/ shared/go/
COPY services/analytics-service/ services/analytics-service/

RUN printf 'go 1.25.0\n\nuse (\n\t./services/analytics-service\n\t./shared/go\n\t./proto/gen/go\n)\n' > go.work

WORKDIR /workspace/services/analytics-service

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -trimpath \
    -o /bin/analytics-service \
    ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

RUN addgroup -S analytics && adduser -S analytics -G analytics

COPY --from=builder /bin/analytics-service /bin/analytics-service

USER analytics

# HTTP REST port / gRPC port
EXPOSE 9006 9008

ENTRYPOINT ["/bin/analytics-service"]
