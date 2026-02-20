
# BUILD STAGE
# ===============================
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git
RUN apk add --no-cache git

# Copy go mod files first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy entire project
COPY . .

# Explicitly copy migrations
COPY migrations ./migrations

# Build binary (IMPORTANT FIX HERE)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o iam-service ./cmd

# ===============================
# RUNTIME STAGE
# ===============================
FROM alpine:3.19

WORKDIR /app

# Create non-root user
RUN addgroup -S app && adduser -S app -G app

# Copy binary from builder
COPY --from=builder /app/iam-service .

# Change ownership
RUN chown -R app:app /app

USER app

EXPOSE 8080

CMD ["./iam-service"]
