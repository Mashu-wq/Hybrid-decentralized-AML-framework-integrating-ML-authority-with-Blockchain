# CLAUDE.md — Blockchain-Based KYC/AML Fraud Detection System

> Thesis project by Mayesha Marzia Zaman Mim. Production-grade platform combining
> Hyperledger Fabric blockchain audit trails with ML-powered fraud intelligence.

---

## 1. Project Architecture at a Glance

```
Internet
   │
   ▼
API Gateway (Traefik, :8080) — JWT auth, rate-limiting, CORS
   │
   ├── IAM Service        (Go, gRPC :50060)  — JWT, RBAC, MFA (TOTP)
   ├── KYC Service        (Go, gRPC :50061)  — Customer onboarding, OCR, blockchain write
   ├── Transaction Svc    (Go, gRPC :50062)  — Kafka consumer, feature extraction, ML call
   ├── Alert Service      (Go, gRPC :50063)  — WebSocket alerts, Kafka consumer
   ├── Case Service       (Go, gRPC :50064)  — SAR generation, S3 upload
   ├── Analytics Service  (Go, gRPC :50065)  — Reports, dashboards
   ├── Blockchain Service (Go, HTTP :9005)   — Hyperledger Fabric Gateway SDK wrapper
   ├── Encryption Service (Go, gRPC :50067)  — HashiCorp Vault transit (AES-256-GCM)
   └── ML Service         (Python, :8000/:50051) — FastAPI + gRPC, fraud models + SHAP/LIME

Hyperledger Fabric Network (3 orgs, 3 channels)
   ├── kyc-channel    — KYC identity records & verification status
   ├── alert-channel  — Fraud alerts & investigation status
   └── audit-channel  — Immutable processing receipts, SAR hashes, model predictions
```

### Data stores

| Store      | Used by                       | Purpose                                      |
|------------|-------------------------------|----------------------------------------------|
| PostgreSQL | IAM, KYC, Alert, Case         | Relational records (users, cases, alerts)    |
| MongoDB    | Transaction Service           | Time-series enriched transactions            |
| Redis      | Transaction, IAM, KYC        | Velocity windows, JWT cache, risk score TTL  |
| Kafka      | Transaction, Alert            | `transactions.raw`, `alerts.created` topics  |
| Vault      | Encryption Service + all      | AES-256-GCM PII encryption at rest           |
| MLflow     | ML Service                    | Model experiment tracking                    |

---

## 2. Repository Layout

```
.
├── services/
│   ├── api-gateway/          # Traefik config + custom Go middleware
│   ├── iam-service/          # Auth, RBAC, JWT, MFA
│   ├── kyc-service/          # Customer onboarding, OCR, blockchain KYC write
│   ├── transaction-service/  # Kafka ingestion, feature extraction, ML gRPC call
│   ├── ml-service/           # FastAPI + gRPC fraud models (Python)
│   │   ├── app/api/          # REST routes (/predict, /explain, /compare)
│   │   ├── app/grpc/         # gRPC server (PredictFraud RPC)
│   │   ├── app/models/       # ModelRegistry — loads & serves trained models
│   │   └── app/features/     # FeaturePipeline — scaler + feature selection
│   ├── blockchain-service/   # Hyperledger Fabric Gateway SDK (Go)
│   ├── alert-service/        # WebSocket push, Kafka consumer, notification dispatch
│   ├── case-service/         # Investigation cases, SAR PDF generation
│   ├── analytics-service/    # Reports and aggregated metrics
│   └── encryption-service/   # Vault transit encrypt/decrypt wrapper
├── blockchain/
│   ├── chaincode/
│   │   ├── kyc-contract/     # KYC lifecycle: RegisterCustomer, UpdateKYCStatus, GetRiskLevel
│   │   ├── alert-contract/   # Fraud alert immutable record + investigation workflow
│   │   └── audit-contract/   # Processing receipts (TRANSACTION_PROCESSED), SAR_FILED, MODEL_PREDICTION
│   └── network/
│       ├── configtx.yaml     # 3-org Raft orderer, MAJORITY block validation
│       ├── crypto-config/    # MSP certs (Org1/PrimaryBank, Org2/Regulator, Org3/PartnerBank)
│       └── connection-profiles/ # Fabric Gateway connection YAML per org
├── ml/
│   ├── data/                 # Elliptic dataset preprocessor (preprocessing.py)
│   ├── features/
│   │   └── engineering.py    # 85-feature selection; domain adaptation to bank wire features
│   ├── models/
│   │   ├── base.py           # FraudModel ABC + SklearnFraudModel mixin
│   │   ├── random_forest.py  # RandomForestClassifier wrapper
│   │   ├── xgboost_model.py  # XGBoostClassifier + Optuna HPO
│   │   ├── lightgbm_model.py # LGBMClassifier + Optuna HPO
│   │   ├── gnn_model.py      # 3-layer GraphSAGE (PyTorch Geometric)
│   │   ├── autoencoder.py    # Deep autoencoder anomaly detector (PyTorch)
│   │   └── ensemble.py       # Weighted-average ensemble + A/B testing hook
│   ├── explainability/
│   │   ├── shap_explainer.py # SHAP TreeExplainer / KernelExplainer
│   │   ├── lime_explainer.py # LIME tabular explainer
│   │   └── counterfactual.py # Counterfactual explanation generator
│   └── evaluation/
│       ├── evaluator.py      # evaluate_model(), compare_models(), COLAB_BENCHMARK
│       └── results/          # pr_curves_all_models.png (Colab training artefact)
├── proto/                    # gRPC .proto definitions (transaction, fraud, kyc, alert, iam…)
├── infrastructure/
│   ├── docker/               # Per-service Dockerfiles
│   ├── kubernetes/           # Helm charts
│   ├── terraform/            # AWS EKS + RDS + MSK + ElastiCache
│   └── monitoring/           # Prometheus alert rules, Grafana dashboards
├── tests/
│   ├── unit/                 # Go + Python unit tests (>80% coverage target)
│   ├── integration/          # Testcontainers-based integration tests
│   └── e2e/                  # Postman collections (api_docs.txt end-to-end guide)
├── docs/
│   ├── methodology.md        # Thesis methodology sections (blockchain vs DB, feature adaptation)
│   └── api_docs.txt          # End-to-end curl testing guide
├── docker-compose.yml        # Full local dev stack
├── Makefile                  # All developer commands (see Section 4)
├── go.work                   # Go workspace (all Go modules)
└── pyproject.toml            # Python deps (Poetry) — ML + ML Service
```

---

## 3. ML Pipeline

### Dataset

- **Elliptic Bitcoin Transaction Dataset** — 203,769 transactions; 46,564 labeled (4,545 illicit, 42,019 licit), 166 features per node plus temporal graph edges.
- Split: 80/20 temporal (time_step-aware, not random) to avoid data leakage.
- Class imbalance handled with SMOTE on the training split.

### Feature Engineering (`ml/features/engineering.py`)

- Raw Elliptic CSV has 166 features. Selection: top 85 by LightGBM importance (feature indices 1–68 and 94–110).
- `SELECTED_FEATURE_NAMES` and `SELECTED_FEATURE_INDICES` are the canonical lists — all models and the gRPC proto contract use this 85-dim vector.
- `_structured_to_elliptic_array()` maps real bank wire transfer fields into 38 of the 85 positions; the remaining 47 are zero-padded (Bitcoin-specific; no bank equivalent).
- Domain adaptation covers 6 FATF Recommendation 16 behavioral categories: value anomaly, velocity, geographic risk, network topology, temporal pattern, customer/KYC profile.

### Models

| Model          | Class                | Key hyperparams                              |
|----------------|----------------------|----------------------------------------------|
| Random Forest  | `RandomForestModel`  | 500 trees, max_depth=12, class_weight=balanced|
| XGBoost        | `XGBoostModel`       | 500 estimators, scale_pos_weight=9, LR=0.05  |
| LightGBM       | `LightGBMModel`      | 1000 leaves, is_unbalance=True, LR=0.05      |
| GNN (GraphSAGE)| `GNNFraudModel`      | 3-layer, 85→256→128→64→2, dropout=0.3        |
| Autoencoder    | `AutoencoderModel`   | 85→64→32→16→32→64→85, inverted scoring       |
| Ensemble       | `EnsembleModel`      | Weighted avg (LGB:0.35, RF:0.33, XGB:0.32)  |

**Autoencoder note:** On the Elliptic dataset, fraud transactions have *lower* reconstruction error than licit (fraud txs have simpler, more uniform features). `inverted=True` is set to account for this.

**GNN production note:** `predict_proba()` uses a self-loop edge index (no message passing) for single-transaction inference. Full graph inference requires `predict_proba_graph()` with a pre-built subgraph.

### Actual Benchmark Results (Colab training run, 2026-06-08)

Elliptic dataset, 80/20 temporal split, SMOTE on training set:

| Model         | Precision | Recall | F1     | ROC-AUC | PR-AUC |
|---------------|-----------|--------|--------|---------|--------|
| LightGBM      | 64.61%    | 68.18% | 66.35% | 96.49%  | 69.7%  |
| Random Forest | 88.34%    | 56.92% | 69.23% | 96.38%  | 68.2%  |
| XGBoost       | 70.64%    | 63.24% | 66.74% | 95.97%  | 69.1%  |
| GNN           | 22.34%    | 66.45% | 33.44% | 88.86%  | 54.7%  |
| Autoencoder   | 6.61%     | 68.15% | 12.05% | 70.94%  | 38.9%  |

> These are the **actual measured results**. README.md targets are aspirational.
> Ensemble results not yet computed from a single run — currently approximated by the weighted-average of the above.

### Explainability

- **SHAP**: TreeExplainer for tree models; KernelExplainer fallback for GNN/Autoencoder.
- **LIME**: `lime_explainer.py` — tabular, fits a local linear model per prediction.
- **Counterfactual**: `counterfactual.py` — generates minimum-perturbation counterfactuals.
- SHAP values are serialised as JSON and stored in PostgreSQL (Alert Service) and on-chain (audit-contract `MODEL_PREDICTION` record).

---

## 4. Common Developer Commands

```bash
# Setup
make infra-up          # Start Docker infra (Postgres, Mongo, Redis, Kafka, Vault, Prometheus, Grafana, MLflow)
make build             # Compile all Go services → ./bin/
make migrate           # Run DB migrations (all services)
make seed              # Seed dev data

# ML
make seed-ml           # Download & preprocess Elliptic dataset
make ml-train          # Train all models, log to MLflow
make ml-evaluate       # Run compare_models(), print table

# Blockchain
make fabric-up         # Start Hyperledger Fabric Docker network
make chaincode-deploy  # Deploy kyc-contract, alert-contract, audit-contract

# Testing
make test              # Unit tests (Go + Python, coverage ≥80%)
make test-integration  # Testcontainers integration tests
make lint              # golangci-lint + flake8

# Running
make run               # Start all Go services
python services/ml-service/main.py  # Start ML service separately
```

---

## 5. Blockchain Architecture

### Network

- 3 organizations: `Org1MSP` (PrimaryBank), `Org2MSP` (Regulator), `Org3MSP` (PartnerBank)
- 3 Raft orderers (one per org): `orderer0`, `orderer1`, `orderer2`
- Block validation: `MAJORITY` — at least 2 of 3 orgs must sign every block
- Measured commit latency: ~400–900 ms (acceptable for async fraud pipeline)

### Channels & Chaincodes

| Channel        | Chaincode      | Key functions                                                     |
|----------------|----------------|-------------------------------------------------------------------|
| `kyc-channel`  | kyc-contract   | RegisterCustomer, UpdateKYCStatus, GetKYCRecord, GetRiskLevel     |
| `alert-channel`| alert-contract | CreateAlert, UpdateAlertStatus, GetAlert, GetCustomerAlerts       |
| `audit-channel`| audit-contract | RecordTransactionProcessed, RecordSARFiled, RecordModelPrediction, GetAuditTrail, GetComplianceReport |

### Fabrication Gap Closure

`RecordTransactionProcessed` is called for **every** ML-scored transaction (not just flagged ones). The regulator's peer independently holds the full audit-channel ledger — absence of a receipt is detectable without trusting the bank.

### Privacy Model

- Customer PII never reaches the ledger — identity stored as `SHA-256(document)`.
- SAR documents stored in S3; only `SHA-256(PDF)` anchored on `audit-channel`.
- All 3 orgs are members of all 3 channels (regulator mandate + cross-institution fraud signal).
- PDC (Private Data Collections) identified as future work for feature-level isolation.

---

## 6. Transaction Processing Pipeline

`transaction-service/internal/service/transaction_service.go` — `ProcessTransaction()`:

1. **Validate** raw transaction input
2. **Feature extraction** — Redis lookups (velocity, last_tx, KYC risk, country history)
3. **ML prediction** — gRPC `PredictFraud` to ML service (heuristic fallback on unavailability)
4. **Redis update** — velocity sorted sets, risk score (5-min TTL)
5. **Alert routing** — if `fraud_probability > threshold[KYC_risk_level]` → publish to Kafka `alerts.created`; FATF risk-based thresholds: high-risk customers use lower thresholds (higher recall)
6. **MongoDB persist** — enriched transaction with features + prediction
7. **Blockchain anchor** — fire-and-forget `AnchorTransactionReceipt()` — never blocks pipeline

---

## 7. Security

| Control                  | Implementation                                              |
|--------------------------|-------------------------------------------------------------|
| PII encryption           | AES-256-GCM via HashiCorp Vault transit engine              |
| Authentication           | JWT access tokens (15 min) + refresh tokens (7 days, Redis) |
| Authorization            | RBAC with per-endpoint fine-grained permissions             |
| Rate limiting            | 100 req/min public; 5 failed logins → 15 min lockout        |
| MFA                      | TOTP (optional per user)                                    |
| SQL injection            | All queries parameterized                                   |
| TLS                      | TLS 1.3 enforced for all inter-service communication (prod) |
| Blockchain immutability  | SHA-256 chained blocks, MAJORITY multi-org signing          |

---

## 8. Local Access Points

| Service        | URL                        | Notes                          |
|----------------|----------------------------|--------------------------------|
| API Gateway    | http://localhost:8080      | JWT from `/auth/login`         |
| ML Service     | http://localhost:8000      | FastAPI Swagger at `/docs`     |
| Grafana        | http://localhost:3000      | admin / see `.env`             |
| Jaeger         | http://localhost:16686     | Distributed tracing            |
| Prometheus     | http://localhost:9090      |                                |
| MLflow         | http://localhost:5000      | Model experiment tracking      |
| Vault UI       | http://localhost:8200      | Token from `.env`              |
| Kafka UI       | http://localhost:8090      | `--profile dev-tools` required |
| Blockchain Svc | http://localhost:9005      | Direct audit verification      |

---

## 9. Proto Contract

All inter-service communication uses gRPC. Proto files in `proto/`:

- `transaction.proto` — IngestTransaction, GetTransaction, GetCustomerHistory, GetRiskScore, GetVelocityStats
- `fraud.proto` — TransactionFeatures (85-dim), FraudPrediction, SHAPContribution
- `kyc.proto` — RegisterCustomer, UpdateKYCStatus, GetKYCRecord
- `alert.proto` — CreateAlert, UpdateAlertStatus, GetAlert
- `iam.proto` — Login, RefreshToken, ValidateToken
- `common.proto` — RiskLevel enum, GeoLocation, PageRequest/Response, SHAPContribution

Generated stubs: `proto/gen/go/` (Go) and `proto/gen/python/` (Python).

---

## 10. Environment Variables

Copy `.env.example` → `.env` before first run. Key variables:

```
POSTGRES_*         DB credentials for IAM, KYC, Alert, Case services
MONGO_*            MongoDB credentials for Transaction Service
REDIS_*            Redis credentials
KAFKA_BROKERS      Kafka bootstrap servers
VAULT_*            Vault token and address for Encryption Service
FABRIC_*           Hyperledger Fabric org/channel/chaincode config
ML_ARTIFACT_DIR    Directory where trained model .pkl/.pt files are stored
MLFLOW_TRACKING_URI MLflow server URL
JWT_SECRET         JWT signing secret
```

---

## 11. Known Limitations & Active Work

- `ml/models/gnn_model.py` — GNN production inference degrades to feature-only MLP (no graph). Full graph inference needs pre-built subgraph from PostgreSQL edge table.
- `ml/features/engineering.py` — 47/85 model input features are zero-padded (Bitcoin-specific). Only 38 map to real bank wire transfer fields.
- Autoencoder performance on Elliptic is poor (AUC 70.9%) due to inverted scoring behaviour; used as a novelty detector, not a primary model.
- Ensemble weights (LGB:0.35, RF:0.33, XGB:0.32) derived from individual ROC-AUC — no joint calibration yet.
- Federated learning stub exists but TensorFlow Federated removed (Python 3.11 compat issue).
- PDC (Private Data Collections) for feature-level regulator-only access is future work.
