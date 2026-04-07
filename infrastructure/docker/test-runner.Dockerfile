# =============================================================================
# Test Runner Dockerfile
# Builds a container with all Go + Python test tooling.
# Used by docker-compose.test.yml for integration tests.
# =============================================================================

FROM golang:1.22-alpine AS go-builder

WORKDIR /app

# Install build deps
RUN apk add --no-cache git make bash

# Copy Go workspace
COPY go.work go.work.sum* ./
COPY shared/ shared/
COPY services/ services/
COPY blockchain/chaincode/ blockchain/chaincode/

# Download dependencies
RUN go work sync && go mod download

# Build test binaries
RUN go build ./...

# =============================================================================
FROM python:3.11-slim AS python-builder

WORKDIR /app

RUN pip install poetry==1.8.3

COPY pyproject.toml poetry.lock* ./
COPY ml/ ml/
COPY services/ml-service/ services/ml-service/

RUN poetry config virtualenvs.in-project true && \
    poetry install --no-interaction --no-ansi --no-root

# =============================================================================
FROM golang:1.22-alpine

RUN apk add --no-cache bash make python3 curl

WORKDIR /app

# Copy go binaries and source
COPY --from=go-builder /usr/local/go /usr/local/go
COPY --from=go-builder /app /app

# Copy Python venv
COPY --from=python-builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY . .

CMD ["make", "test-integration"]
