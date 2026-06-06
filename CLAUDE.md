# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Production-grade **Blockchain-Based KYC/AML Fraud Detection System** (thesis project). Combines Hyperledger Fabric for immutable audit trails with ensemble ML fraud detection (XGBoost, LightGBM, Random Forest, GNN, Autoencoder) trained on the Elliptic Bitcoin dataset.

## Common Commands

All developer workflows go through `make`. Run `make help` for the full list.

### Bootstrap
```bash
bash scripts/setup.sh   # One-command idempotent full local setup
cp .env.example .env    # Configure environment variables
```

### Infrastructure
```bash
make infra-up           # Start Docker stack (postgres, mongo, redis, kafka, vault, etc.)
make infra-down         # Stop containers (keep volumes)
make infra-clean        # Destroy containers + volumes (destructive)
make infra-status       # Show container status
make health             # Check health of all running services
```

### Build
```bash
make build                        # Build all 9 Go services
make build-svc SVC=iam-service    # Build a single Go service
make build-ml                     # Install Python ML dependencies (Poetry)
make proto                        # Regenerate gRPC stubs (Go + Python) from /proto/*.proto
```

### Run
```bash
make run                          # Start all services via docker-compose
make run-svc SVC=iam-service      # Run a single service locally
make fabric-up                    # Start Hyperledger Fabric network separately
```

### Testing
```bash
make test                         # All unit tests
make test-unit-go                 # Go unit tests with coverage
make test-unit-python             # Python unit tests (from tests/unit/)
make test-unit-chaincode          # Chaincode tests
make test-integration             # Integration tests (requires Docker)
make test-e2e                     # E2E tests (Postman collections via Newman)
make test-perf                    # Locust performance tests
make test-security                # gosec + bandit security scan
make test-coverage                # Open coverage reports
```

#### Run a single Go service's tests
```bash
cd services/iam-service && go test -v -race ./...
cd services/transaction-service && go test -v -run TestProcessTransaction ./internal/service/...
```

#### Run chaincode tests
```bash
cd blockchain/chaincode/kyc-contract && go test -v -race ./...
```

#### Run Python tests for ml-service
```bash
cd services/ml-service && poetry run pytest tests/unit/test_ensemble.py -v
```

### Lint & Format
```bash
make lint                         # All linters (golangci-lint + flake8 + black + mypy)
make lint-go                      # Go only (.golangci.yml config)
make lint-python                  # flake8 + black + mypy
make fmt                          # Auto-format (gofmt + black + isort)
```

### Database
```bash
make migrate                      # Run all migrations
make migrate-down                 # Rollback last migration
make seed                         # Seed development data
make seed-ml                      # Download Elliptic Bitcoin dataset
```

### ML
```bash
make ml-train                             # Train all models
make ml-train-model MODEL=xgboost         # Train a specific model
make ml-evaluate                          # Generate model comparison table
make ml-serve                             # Run ML service locally (FastAPI + gRPC)
```

### Blockchain
```bash
make fabric-up                    # Start Hyperledger Fabric (3-org network)
make chaincode-deploy             # Deploy kyc-contract, alert-contract, audit-contract
make fabric-down                  # Stop and clean Fabric network
```

## Architecture

### Services (`/services/`)
10 microservices communicating over **gRPC** (proto definitions in `/proto/`):

| Service | Language | Responsibility |
|---|---|---|
| `api-gateway` | Go | Traefik + JWT auth, rate limiting, CORS |
| `iam-service` | Go | Authentication, RBAC, JWT, TOTP MFA |
| `kyc-service` | Go | Customer onboarding, OCR, face verification |
| `transaction-service` | Go | Kafka consumer, feature extraction |
| `ml-service` | Python | FastAPI + gRPC, ensemble fraud models, SHAP/LIME |
| `blockchain-service` | Go | Hyperledger Fabric SDK wrapper |
| `alert-service` | Go | Alert generation, WebSocket notifications |
| `case-service` | Go | Case management, SAR generation |
| `analytics-service` | Go | Reports, metrics aggregation |
| `encryption-service` | Go | HashiCorp Vault Transit wrapper (AES-256-GCM) |

### Go Workspace & Module Layout
`go.work` ties 11 modules: 9 Go services + `shared/go` + `proto/gen/go`. Each service uses import path `github.com/fraud-detection/<service-name>`; shared library is `github.com/fraud-detection/shared`.

Every Go service follows the same internal layer pattern:
```
services/<name>/
  cmd/            # main.go — wires up dependencies
  internal/
    config/       # env-based config struct
    domain/       # core types, no external dependencies
    grpc/         # gRPC server handler (calls service layer)
    repository/   # PostgreSQL/MongoDB/Redis adapters
    service/      # business logic — depends only on interfaces defined in service.go
```

Service layer files define port interfaces (e.g. `TransactionStore`, `FraudPredictor`) to enforce dependency inversion; implementations in `repository/` satisfy those interfaces, enabling unit testing with mocks.

### Request Flow
1. **API Gateway** validates JWT by calling IAM service; caches validated claims by SHA-256(token). Public paths (login, register, refresh, health) bypass auth.
2. Gateway injects `RequestMetadata` (trace ID, user ID, role) into outbound gRPC headers via shared `middleware` interceptors.
3. **Transaction Service** consumes `transactions.raw` Kafka topic with a worker-pool consumer. For each message: extract features → call ML Service (gRPC `PredictFraud`) → update Redis velocity counters → persist to MongoDB → publish to `alerts.created` if fraud probability exceeds threshold.
4. ML prediction failures fall back to a heuristic rule (non-blocking); storage failures are logged but do not roll back the in-memory result.
5. **Alert Service** consumes `alerts.created` → pushes WebSocket notifications + Kafka `notifications.outbound`.
6. **Blockchain Service** anchors KYC records and alerts on Hyperledger Fabric.

### Blockchain (`/blockchain/`)
- **Hyperledger Fabric 2.x**, 3 organizations (Primary Bank / Regulator / Partner)
- 3 channels: `kyc-channel`, `alert-channel`, `audit-channel`
- 3 Go chaincodes: `kyc-contract`, `audit-contract`, `alert-contract`
- Chaincodes use composite keys and Fabric events (e.g. `KYC_REGISTERED`) for off-chain indexing
- Each chaincode is its own Go module under `blockchain/chaincode/<name>/`

### ML Pipeline (`/ml/`)
- **Dataset**: Elliptic Bitcoin Transactions (203K txs, 166 features, temporal graph)
- **Models**: `random_forest.py`, `xgboost_model.py`, `lightgbm_model.py`, `gnn_model.py`, `autoencoder.py`, `ensemble.py` — all extend `base.FraudModel`
- **Ensemble weights** (ROC-AUC based): LightGBM 0.35, RF 0.33, XGBoost 0.32; supports A/B challenger routing via `ab_ratio`
- **Targets**: >94% precision, >90% recall, >0.98 AUC-ROC
- **Explainability**: SHAP (top-5 features) + LIME per prediction at `ml/explainability/`
- **Registry**: MLflow at `http://localhost:5000`
- ML training code lives in `/ml/`; the deployed service lives in `/services/ml-service/` (FastAPI + gRPC)

### Event Bus (Kafka Topics)
`kyc.events` · `transactions.raw` · `alerts.created` · `audit.events` · `blockchain.events` · `notifications.outbound`

### Data Stores
- **PostgreSQL 15** — KYC, IAM, alerts, cases (relational)
- **MongoDB 6** — transaction time-series
- **Redis 7** — sessions, caching, rate limiting, bloom filters, velocity counters (sorted sets)

### Security Model
- All PII encrypted via **Encryption Service → Vault Transit** before DB storage
- JWT: 15min access tokens + 7-day refresh tokens stored in Redis
- Rate limit: 100 req/min public; 5 failed logins → 15min lockout (tracked in `User.FailedAttempts` / `LockedUntil`)
- RBAC roles: `ADMIN`, `ANALYST`, `INVESTIGATOR`, `AUDITOR`, `API_CLIENT`

### Shared Go Libraries (`/shared/go/`)
- `logger/` — structured logging (zerolog)
- `tracing/` — OpenTelemetry instrumentation
- `middleware/` — gRPC interceptors (auth, logging, tracing)
- `grpcclient/` — shared gRPC dial helpers

### Lint Configuration (`.golangci.yml`)
Strict mode. Key rules: line length 120, cyclomatic complexity 15. Test files get relaxed rules for `gomnd`, `dupl`, `wrapcheck`. Generated proto files (`proto/gen/`) are excluded entirely. `godox` is disabled (TODO comments are expected).

## Key Files
- `go.work` — Go workspace (11 modules)
- `pyproject.toml` — root Python config for `/ml/` training pipeline; `services/ml-service/pyproject.toml` — deployed ML service deps (Poetry)
- `.golangci.yml` — Go linter configuration
- `docker-compose.yml` — full local dev stack (13+ containers)
- `docker-compose.test.yml` — isolated test environment
- `.env.example` — all required environment variables (copy to `.env`)
- `blockchain/network/configtx.yaml` — Fabric channel and org configuration
- `proto/*.proto` — source of truth for all inter-service contracts
- `worklog.md` — phase-by-phase implementation history and architecture decision log

## Local Dev Endpoints (after `make run`)
| Service | URL |
|---|---|
| API Gateway | http://localhost:8080 |
| Grafana | http://localhost:3000 |
| Jaeger | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
| MLflow | http://localhost:5000 |
| Vault UI | http://localhost:8200 |
| Kafka UI | http://localhost:8090 (dev-tools profile) |
