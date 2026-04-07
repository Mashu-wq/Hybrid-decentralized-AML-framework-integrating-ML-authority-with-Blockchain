# Blockchain-Based KYC/AML Fraud Detection System

> **Thesis Project** — A production-grade fraud detection platform combining Hyperledger Fabric blockchain for immutable audit trails with ML-powered fraud intelligence (XGBoost, LightGBM, GNN, Ensemble).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        API Gateway (Traefik)                        │
│            Rate Limiting · JWT Auth · Tracing · CORS               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
          ┌──────────────────┼───────────────────┐
          │                  │                   │
   ┌──────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
   │ IAM Service │   │ KYC Service  │   │  TX Service  │
   │  JWT · MFA  │   │ OCR · Face   │   │  Kafka Csmr  │
   └──────┬──────┘   └───────┬──────┘   └───────┬──────┘
          │                  │                   │
          │           ┌──────▼──────┐            │
          │           │  Encrypt.   │            │
          │           │   Service   │            │
          │           │    Vault    │            │
          │           └──────┬──────┘            │
          │                  │                   │
   ┌──────▼──────────────────▼───────────────────▼──────┐
   │                   ML Service (Python)               │
   │   XGBoost · LightGBM · GNN · Autoencoder · SHAP   │
   └──────────────────────────┬──────────────────────────┘
                              │
          ┌───────────────────┼───────────────┐
          │                   │               │
   ┌──────▼──────┐   ┌────────▼──────┐  ┌────▼────────┐
   │Alert Service│   │ Case Service  │  │  Analytics  │
   │ WebSocket   │   │ SAR · Evidence│  │  Reports    │
   └──────┬──────┘   └────────┬──────┘  └─────────────┘
          │                   │
   ┌──────▼───────────────────▼──────┐
   │     Blockchain Service          │
   │    Hyperledger Fabric SDK       │
   └──────────────────────────────────┘
          │
   ┌──────▼──────────────────────────────────────────────┐
   │              Hyperledger Fabric Network             │
   │  Org1(PrimaryBank) · Org2(Regulator) · Org3(Partner)│
   │  KYC Channel · Alert Channel · Audit Channel        │
   └──────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | ≥ 1.22 | https://go.dev/dl/ |
| Python | ≥ 3.11 | https://python.org |
| Docker | ≥ 24.0 | https://docs.docker.com/get-docker/ |
| make | any | system package manager |

### One-Command Bootstrap

```bash
git clone https://github.com/your-org/fraud-detection-system
cd fraud-detection-system

# Bootstrap everything (installs deps, starts Docker infra, runs migrations)
bash scripts/setup.sh
```

### Manual Steps

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your secrets

# 2. Start infrastructure
make infra-up

# 3. Build all Go services
make build

# 4. Run database migrations
make migrate

# 5. Seed development data
make seed

# 6. Prepare Elliptic dataset + train ML models
make seed-ml
make ml-train

# 7. Start all services
make run
```

### Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| API Gateway | http://localhost:8080 | JWT token from /auth/login |
| Grafana | http://localhost:3000 | admin / (see .env) |
| Jaeger | http://localhost:16686 | — |
| Prometheus | http://localhost:9090 | — |
| MLflow | http://localhost:5000 | — |
| Vault UI | http://localhost:8200 | Token from .env |
| Kafka UI | http://localhost:8090 | start with `--profile dev-tools` |

## Project Structure

```
fraud-detection-system/
├── services/
│   ├── api-gateway/          # Traefik + custom middleware
│   ├── iam-service/          # Auth, RBAC, JWT, MFA (Go)
│   ├── kyc-service/          # Customer onboarding, OCR (Go)
│   ├── transaction-service/  # Kafka ingestion, feature extraction (Go)
│   ├── ml-service/           # FastAPI + gRPC fraud models (Python)
│   ├── blockchain-service/   # Hyperledger Fabric SDK (Go)
│   ├── alert-service/        # Alerts, WebSocket, notifications (Go)
│   ├── case-service/         # Cases, SAR generation (Go)
│   ├── analytics-service/    # Reports, metrics (Go)
│   └── encryption-service/   # Vault transit encryption (Go)
├── blockchain/
│   ├── chaincode/            # Go chaincodes (KYC, Alert, Audit)
│   └── network/              # Fabric network config (3 orgs)
├── ml/
│   ├── data/                 # Elliptic dataset preprocessing
│   ├── features/             # Feature engineering pipeline
│   ├── models/               # RF, XGBoost, LightGBM, GNN, Autoencoder, Ensemble
│   ├── explainability/       # SHAP + LIME
│   ├── federated/            # Federated learning stub
│   └── evaluation/           # Benchmarks and comparison table
├── proto/                    # gRPC .proto definitions
├── infrastructure/
│   ├── kubernetes/           # Helm charts
│   ├── terraform/            # AWS EKS, RDS, MSK, ElastiCache
│   ├── docker/               # Dockerfiles
│   └── monitoring/           # Prometheus rules, Grafana dashboards
├── tests/
│   ├── unit/                 # Unit tests (>80% coverage target)
│   ├── integration/          # Testcontainers integration tests
│   └── e2e/                  # Postman collections
├── scripts/                  # Bootstrap, seed, and run scripts
├── docs/                     # Architecture diagrams, API spec
├── docker-compose.yml        # Local development environment
└── Makefile                  # All developer commands
```

## ML Model Performance Targets

| Model | Precision | Recall | F1 Score | AUC-ROC |
|-------|-----------|--------|----------|---------|
| Random Forest | >88% | >82% | >85% | >0.93 |
| XGBoost | >91% | >86% | >88.5% | >0.95 |
| LightGBM | >90% | >85% | >87.5% | >0.94 |
| GNN (GraphSAGE) | >93% | >89% | >91% | >0.97 |
| **Ensemble** | **>94%** | **>90%** | **>92%** | **>0.98** |

Dataset: [Elliptic Bitcoin Transaction Dataset](https://www.kaggle.com/datasets/ellipticco/elliptic-data-set)
- 203,769 transactions (46,564 labeled: 4,545 illicit, 42,019 licit)
- 166 features per transaction
- Temporal graph structure

## Key Commands

```bash
make help              # List all available commands
make infra-up          # Start Docker infrastructure
make build             # Build all Go services
make test              # Run unit tests
make test-integration  # Run integration tests (needs Docker)
make lint              # Run all linters (golangci-lint + flake8)
make ml-train          # Train all ML models
make ml-evaluate       # Generate model comparison table
make fabric-up         # Start Hyperledger Fabric network
make chaincode-deploy  # Deploy all chaincodes
make docs              # Generate API documentation
```

## Security

- All PII encrypted with AES-256-GCM via HashiCorp Vault Transit engine
- JWT access tokens (15min) + refresh tokens (7 days) stored in Redis
- RBAC with fine-grained permissions per endpoint
- Rate limiting: 100 req/min public, 5 failed login attempts → 15min lockout
- MFA (TOTP) optional per user
- All DB queries use parameterized statements
- TLS 1.3 enforced for all inter-service communication (production)

## Implementation Phases

- [x] **Phase 1**: Project Foundation & Infrastructure
- [x] **Phase 2**: Proto Contracts & gRPC Setup
- [x] **Phase 3**: IAM Service
- [x] **Phase 4**: Encryption Service
- [ ] **Phase 5**: KYC Service
- [ ] **Phase 6**: Hyperledger Fabric Network + Chaincode
- [ ] **Phase 7**: ML Service
- [ ] **Phase 8**: Transaction Monitoring Service
- [ ] **Phase 9**: Alert & Notification Service
- [ ] **Phase 10**: Case Management Service
- [ ] **Phase 11**: API Gateway
- [ ] **Phase 12**: Analytics & Reporting Service
- [ ] **Phase 13**: Testing Suite
- [ ] **Phase 14**: Kubernetes & Infrastructure
- [ ] **Phase 15**: CI/CD & Monitoring

## License

MIT License — Thesis research project.
