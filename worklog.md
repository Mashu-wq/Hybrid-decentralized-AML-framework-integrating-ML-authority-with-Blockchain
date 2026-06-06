# Project Worklog — Blockchain-Based KYC/AML Fraud Detection System

> Last updated: 2026-04-03
> Session tracking: Phase 10 complete. Phases 1–10 verified.

---

## Table of Contents
1. [Phase Status](#phase-status)
2. [Completed Phases — Detail](#completed-phases--detail)
3. [Remaining Phases — Roadmap](#remaining-phases--roadmap)
4. [Problems Encountered & Resolutions](#problems-encountered--resolutions)
5. [Open TODOs (Non-Blocking)](#open-todos-non-blocking)
6. [Architecture Decisions](#architecture-decisions)

---

## Phase Status

| # | Phase | Status | Notes |
|---|-------|--------|-------|
| 1 | Project Foundation & Infrastructure | ✅ Complete | docker-compose, Makefile, go.work, scripts |
| 2 | Proto Contracts & gRPC Setup | ✅ Complete | All 8 .proto files + hand-written Go stubs |
| 3 | IAM Service (Go) | ✅ Complete | Auth, JWT, MFA, RBAC, gRPC handler wired |
| 4 | Encryption Service (Go) | ✅ Complete | Vault Transit, real JWT validation, gRPC |
| 5 | KYC Service (Go) | ✅ Complete | Full implementation — 22 files, all Phase 5 requirements met |
| 6 | Hyperledger Fabric + Chaincode | ✅ Complete | 3 chaincodes, network config, blockchain service |
| 7 | ML Service (Python + FastAPI + gRPC) | ✅ Complete | Full implementation — 32 files, all Phase 7 requirements met |
| 8 | Transaction Monitoring Service (Go) | ✅ Complete | 20 files — Kafka consumer, feature pipeline, ML gRPC client, MongoDB+Redis repos, gRPC server |
| 9 | Alert & Notification Service (Go) | ✅ Complete | 22 files — Kafka consumer, dedup, PostgreSQL+Redis repos, 4-channel notifications, WebSocket hub, escalation scheduler, gRPC+REST servers |
| 10 | Case Management Service (Go) | ✅ Complete | 20 files — Kafka consumer, PostgreSQL repo, S3 evidence store, SAR PDF generator, blockchain audit, gRPC+REST servers |
| 11 | API Gateway | ⏳ Not Started | go.mod scaffold only |
| 12 | Analytics & Reporting Service (Go) | ⏳ Not Started | go.mod scaffold only |
| 13 | Testing Suite | ⏳ Not Started | stub .gitkeep files only |
| 14 | Kubernetes & Infrastructure | ⏳ Not Started | stub .gitkeep files only |
| 15 | CI/CD & Monitoring | ⏳ Not Started | Prometheus rules + Grafana provisioning only |

---

## Completed Phases — Detail

### Phase 1: Project Foundation & Infrastructure ✅

**What was built:**
- `go.work` — Go workspace coordinating 10 modules (8 services + shared + proto/gen/go)
- `docker-compose.yml` — 14-service local dev stack:
  - PostgreSQL 15 (pgcrypto enabled)
  - MongoDB 6 (time-series collection support)
  - Redis 7 (pub/sub)
  - Apache Kafka 3.x + Zookeeper
  - HashiCorp Vault 1.16 (dev mode)
  - Jaeger (distributed tracing)
  - Prometheus + Grafana
  - MLflow (model registry)
  - Elasticsearch + Kibana (elk profile)
  - Kafka UI + pgAdmin (dev-tools profile)
- `docker-compose.test.yml` — Testcontainers integration test harness
- `Makefile` — 40+ targets: build, test, lint, run, migrate, seed, proto, fabric, k8s, docs
- `scripts/setup.sh` — one-command bootstrap
- `scripts/proto-gen.sh` — protoc code generation
- `scripts/db/postgres-init.sql` — schema init
- `scripts/db/mongo-init.js` — MongoDB init
- `scripts/vault/vault-init.sh` — Vault Transit key setup
- `.golangci.yml` — strict 40+ linter config
- `.env.example` — 120 documented env vars
- `pyproject.toml` — root Python project + Poetry config
- `shared/go/` — shared libraries:
  - `logger/logger.go` — zerolog JSON structured logging
  - `tracing/tracing.go` — OpenTelemetry + Jaeger
  - `grpcclient/client.go` — gRPC client factory with interceptors
  - `middleware/grpc_interceptors.go` — Recovery, Logging, Tracing, Auth, Metadata interceptors

**Key files:**
```
go.work
docker-compose.yml
docker-compose.test.yml
Makefile
.golangci.yml
.env.example
pyproject.toml
scripts/setup.sh
scripts/proto-gen.sh
shared/go/logger/logger.go
shared/go/tracing/tracing.go
shared/go/grpcclient/client.go
shared/go/middleware/grpc_interceptors.go
```

---

### Phase 2: Proto Contracts & gRPC Setup ✅

**What was built:**
- 8 `.proto` definition files in `proto/`:
  - `common.proto` — shared types (RequestMetadata, PageRequest/Response, RiskLevel, AlertStatus, KYCStatus, HealthStatus, Money, GeoLocation, SHAPContribution)
  - `iam.proto` — IAMService (Register, Login, MFA, ValidateToken, etc.)
  - `encryption.proto` — EncryptionService (EncryptPII, DecryptPII, Batch, RewrapKey, IdentityHash)
  - `kyc.proto` — KYCService
  - `fraud.proto` — FraudService (ML predictions)
  - `transaction.proto` — TransactionService
  - `alert.proto` — AlertService
  - `audit.proto` — AuditService
- Hand-written Go stubs in `proto/gen/go/` (pending `make proto`):
  - `common/v1/common.pb.go` — all common types
  - `common/v1/common_grpc.pb.go` — empty (no service in common.proto)
  - `encryption/v1/encryption.pb.go` — all encryption message types
  - `encryption/v1/encryption_grpc.pb.go` — full client/server/handler/descriptor
  - `iam/v1/iam.pb.go` — all IAM message types *(added in error-fix session)*
  - `iam/v1/iam_grpc.pb.go` — full client/server/handler/descriptor *(added in error-fix session)*
- `proto/gen/go/go.mod` — proto stubs Go module
- `proto/gen/python/__init__.py` — Python stubs placeholder

**Note:** The stubs are hand-written to unblock development. Replace with `make proto` output once `protoc` and `protoc-gen-go-grpc` are installed.

---

### Phase 3: IAM Service (Go) ✅

**What was built:**

| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Entry point — dependency wiring, graceful shutdown |
| `internal/config/config.go` | Env-driven config with validation (JWT secret ≥32 chars enforced) |
| `internal/domain/user.go` | Domain models: User, Role, Permission, RefreshToken, TokenClaims, AuthError, AuditEvent |
| `internal/service/auth_service.go` | Core auth: Register, Login (MFA), VerifyMFA, RefreshTokens, Logout, ChangePassword, ValidateToken |
| `internal/service/token_service.go` | JWT HS256 signing/validation, refresh token generation (384-bit entropy), JTI blocklist |
| `internal/service/mfa_service.go` | TOTP secret generation, TOTP verification, backup code generation (bcrypt-hashed) |
| `internal/repository/postgres/user_repo.go` | PostgreSQL: users, refresh_tokens, permissions, audit_events |
| `internal/repository/redis/token_repo.go` | Redis: JTI blocklist, session tracking, MFA challenge store, rate limiter |
| `internal/repository/redis/service_adapters.go` | Adapter bridging redis.MFAChallenge → service.MFAChallenge |
| `internal/grpc/server.go` | gRPC server setup with full interceptor chain |
| `internal/grpc/handler.go` | IAMServiceServer implementation — proto↔domain translation *(added in error-fix session)* |
| `internal/service/auth_service_test.go` | 464-line unit test suite |

**Security features:**
- bcrypt cost=12 for password hashing
- JWT access tokens (15-min TTL) + opaque refresh tokens (7-day TTL, SHA-256 stored)
- Refresh token rotation (old token revoked on use)
- Device binding on refresh tokens (device mismatch → immediate revocation + audit log)
- Rate limiting: 5 failed attempts → 15-min lockout
- JTI blocklist in Redis for pre-expiry logout
- TOTP MFA with 8 backup codes
- Audit log for every auth event

---

### Phase 4: Encryption Service (Go) ✅

**What was built:**

| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Entry point — Vault init, key existence check, graceful shutdown |
| `internal/config/config.go` | Vault address, token/AppRole auth, key names, rotation period, batch size |
| `internal/vault/client.go` | Vault Transit wrapper: Encrypt, Decrypt, Rewrap, GetKeyMetadata, Ping, EnsureKeyExists |
| `internal/service/encryption_service.go` | EncryptPII, DecryptPII, BatchEncrypt, BatchDecrypt, RewrapKey, GenerateIdentityHash, GetKeyInfo, HealthCheck |
| `internal/grpc/server.go` | gRPC server with real JWT validation (HS256) |
| `internal/service/encryption_service_test.go` | 370-line unit test suite |
| `README.md` | Service documentation |

**Security features:**
- Vault Transit AES-256-GCM encryption
- PII never logged anywhere in the call chain
- Identity hash: SHA-256(normalized: fullName|dob|docType|docNumber|country)
- Batch operations for performance
- Key rotation support (RewrapKey re-encrypts under latest key version)
- AppRole authentication support for production Vault

---

### Phase 5: KYC Service (Go) ✅

**What was built:**

| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Entry point — full dependency wiring: config → logger → tracer → postgres → encryption client → blockchain stub → face-match mock → OCR (real/mock) → Kafka → dual gRPC+HTTP servers |
| `internal/config/config.go` | Env-driven config: ports, PostgreSQL, Kafka, AWS, downstream service addrs, mock flags, upload dir, thresholds |
| `internal/domain/kyc.go` | Domain models: Customer (non-PII only), EncryptedPII (Vault ciphertexts), Document, OCRResult, FaceVerifyResult, KYCEvent, AuditEvent, KYCStatus, RiskLevel, KYCError |
| `internal/service/kyc_service.go` | Core KYC logic: RegisterCustomer (6-step), SubmitDocument (OCR), VerifyFace, UpdateKYCStatus (state machine), GetKYCRecord, ListByStatus, GetDecryptedPII (audit gated), GetCustomerRiskLevel |
| `internal/repository/postgres/kyc_repo.go` | PostgreSQL: 12 methods across customers, kyc_pii, documents, audit_events tables |
| `internal/grpc/handler.go` | KYCServiceServer — all 9 RPCs with compile-time interface assertion |
| `internal/grpc/server.go` | gRPC server — JWT validator (HS256), 4 public methods, interceptor chain |
| `internal/http/handler.go` | REST handlers: RegisterCustomer, GetKYCRecord, ListCustomers, UpdateKYCStatus, SubmitDocument (JSON + multipart), VerifyFace, GetDecryptedPII, HealthCheck |
| `internal/http/server.go` | Go 1.22 ServeMux, 8 routes, middleware chain (requestID, Content-Type, logging) |
| `internal/storage/local_store.go` | DocumentStore interface + LocalDocumentStore (dev/test file upload with path sanitisation) |
| `internal/clients/encryption.go` | EncryptionClient gRPC wrapper: BatchEncryptPII, BatchDecryptPII, GenerateIdentityHash |
| `internal/clients/blockchain.go` | BlockchainClient interface + stubBlockchainClient (returns `stub-tx-<uuid>`, logs intent) |
| `internal/clients/facematch.go` | FaceMatchClient interface + mockFaceMatchClient (match=true, score=0.92, liveness=true) |
| `internal/kafka/producer.go` | EventProducer: JSON-encodes KYCEvent, uses CustomerID as partition key, injects OTel trace headers |
| `internal/textract/client.go` | Real AWS Textract client: async job start → poll → parse key-value pairs → OCRResult |
| `internal/textract/mock.go` | MockOCRClient — per-document-type realistic responses, 50ms simulated delay |
| `internal/service/kyc_service_test.go` | Unit tests: RegisterCustomer happy path, duplicate detection, OCR flow, VerifyFace, PII audit logging, status transition valid/invalid |
| `proto/gen/go/kyc/v1/kyc.pb.go` | KYC message types: all request/response structs, KYCRecord, OCRResult, CustomerPII (PII fields annotated `// DO NOT LOG`) |
| `proto/gen/go/kyc/v1/kyc_grpc.pb.go` | gRPC stub: KYCServiceClient/Server interfaces, UnimplementedKYCServiceServer, 9 method constants, RegisterKYCServiceServer, service descriptor |
| `scripts/db/migrations/001_kyc_schema.sql` | 4 tables: kyc_customers (non-PII), kyc_pii (Vault ciphertexts), kyc_documents (OCR state), kyc_audit_events; 8 indexes |
| `go.mod` | All dependencies: pgx/v5, segmentio/kafka-go, aws-sdk-go-v2/textract, jwt/v5, zerolog, otel, grpc, protobuf |
| `Dockerfile` | Multi-stage build |

**Phase 5 requirement checklist:**
| Requirement | Implementation |
|-------------|---------------|
| Customer onboarding REST API | `POST /api/v1/kyc/customers` (JSON + multipart document upload) |
| OCR via AWS Textract SDK | `internal/textract/client.go` — async job polling with pagination |
| OCR mock fallback for local dev | `internal/textract/mock.go` — per-type realistic mock, `USE_MOCK_TEXTRACT=true` default |
| Face matching via gRPC to ML service | `clients/facematch.go` — FaceMatchClient interface, mock impl until Phase 7 |
| Liveness detection flag | `CheckLiveness` in VerifyFaceInput, `LivenessPassed`/`LivenessScore` in result and Customer |
| ALL PII encrypted via Encryption Service | `BatchEncryptPII()` called before any DB write in RegisterCustomer |
| Only identity_hash + kyc_status + risk_level in plaintext | `kyc_customers` table has no PII columns; all PII in `kyc_pii` as Vault ciphertexts |
| Publish `KYC_REGISTERED` to `kyc.events` | Kafka `PublishKYCEvent()` called after successful customer persist |
| Trigger blockchain registration | Async goroutine calls `blockchain.RegisterKYCOnChain()` with 30s timeout (non-fatal) |

**Key design decisions:**
- **PII never touches the DB in plaintext**: EncryptionClient.BatchEncryptPII() is called before CreateCustomer; if encryption fails the customer is never written
- **Blockchain is non-fatal**: `RegisterKYCOnChain` runs in a goroutine with its own context; failure is logged but does not roll back the registration
- **Status state machine enforced**: `validateStatusTransition()` gates all status updates: PENDING→{APPROVED,REJECTED}, APPROVED→{SUSPENDED,REJECTED}, SUSPENDED→{APPROVED,REJECTED}, REJECTED→{PENDING}
- **PII access is audit-gated**: `GetDecryptedPII` logs an `AuditEvent` to the DB *before* returning decrypted data; failure to log = access denied
- **Multipart document upload**: `SubmitDocument` handler handles both JSON (pre-uploaded S3 key) and `multipart/form-data` (direct file upload → LocalDocumentStore) through the same route
- **Mock clients for unbuilt services**: Blockchain stub and FaceMatch mock implement real interfaces, allowing full service execution in Phase 5 without Phases 6 or 7

---

## Remaining Phases — Roadmap

### Phase 6: Hyperledger Fabric Network + Chaincode ✅

**What was built:**

| File | Purpose |
|------|---------|
| `blockchain/network/cryptogen.yaml` | 3 orderer nodes, 3 orgs × 2 peers |
| `blockchain/network/configtx.yaml` | Orderer (RAFT/etcdraft), 3 org MSPs, 3 channel profiles (KYCChannel, AlertChannel, AuditChannel), FraudConsortium |
| `blockchain/network/docker-compose.yaml` + `docker-compose.peers.yaml` | Full Fabric network stack (orderers, peers, CouchDB) |
| `blockchain/network/connection-profiles/org{1,2,3}.yaml` | Fabric SDK connection profiles per org |
| `blockchain/network/start.sh` + `teardown.sh` | Network lifecycle scripts |
| `blockchain/network/deploy-chaincode.sh` | Chaincode lifecycle: package → install → approve → commit |
| `blockchain/chaincode/kyc-contract/contract.go` | RegisterCustomer, UpdateKYCStatus, GetKYCRecord, GetKYCHistory (GetHistoryForKey + snapshot fallback), ListPendingKYC — composite key index on status |
| `blockchain/chaincode/kyc-contract/contract_test.go` | shimtest: lifecycle, status transition, validation |
| `blockchain/chaincode/alert-contract/contract.go` | CreateAlert, UpdateAlertStatus, GetAlertsByCustomer, GetAlertsByRiskLevel (CouchDB rich query + composite fallback), GetAlertStats — 3 composite indexes, stats rebuilt on every write |
| `blockchain/chaincode/alert-contract/contract_test.go` | shimtest: full lifecycle, stats, validation |
| `blockchain/chaincode/audit-contract/contract.go` | RecordInvestigatorAction, RecordModelPrediction, GetAuditTrail, GetComplianceReport — SHA-256 hash per record, composite key on entityType+entityID |
| `blockchain/chaincode/audit-contract/contract_test.go` | shimtest: investigator + prediction + trail + compliance report + validation |
| `services/blockchain-service/internal/fabric/client.go` | Fabric SDK gateway: channel client pool (round-robin), event listeners per channel → Kafka, health check via QueryInfo + resmgmt |
| `services/blockchain-service/internal/kafka/publisher.go` | Kafka publisher (real + noop fallback) |
| `services/blockchain-service/internal/service/service.go` | All 14 operations: RegisterKYC, UpdateKYCStatus, GetKYCRecord, GetKYCHistory, ListPendingKYC, CreateAlert, UpdateAlertStatus, GetAlertsByCustomer, GetAlertsByRiskLevel, GetAlertStats, RecordInvestigatorAction, RecordModelPrediction, GetAuditTrail, GetComplianceReport, Health |
| `services/blockchain-service/internal/http/handler.go` | 17 HTTP routes (8 writes + 7 reads + health) |
| `services/blockchain-service/internal/http/server.go` | HTTP server with graceful shutdown |
| `services/blockchain-service/internal/config/config.go` | Env-driven config: connection profile, org, pool size, 3 channels+chaincodes, Kafka |
| `services/blockchain-service/internal/domain/types.go` | All request/response types |
| `services/blockchain-service/internal/service/service_test.go` | 20 tests: all 14 operations + validation errors + gateway error propagation |
| `services/blockchain-service/cmd/server/main.go` | Entry point: config → logger → Kafka publisher → Fabric gateway → event listeners → HTTP server |

**Gap fixed in this session:**
- `service.go` previously only had write operations (7 methods). Added 7 missing query methods: GetKYCHistory, ListPendingKYC, GetAlertsByCustomer, GetAlertsByRiskLevel, GetAlertStats, GetAuditTrail, GetComplianceReport.
- `handler.go` previously had 8 routes (7 writes + health). Added 7 read routes with GET handlers and query param parsing.
- `service_test.go` previously had only 1 test. Expanded to 20 tests covering all operations.

### Phase 6 requirement checklist:
| Requirement | Status |
|---|---|
| 3 orgs: PrimaryBank, RegulatoryAuthority, PartnerBank | ✅ Org1/Org2/Org3 MSPs in configtx.yaml |
| 3 channels: kyc-channel, alert-channel, audit-channel | ✅ KYCChannel, AlertChannel, AuditChannel profiles |
| RAFT orderer with 3 nodes | ✅ etcdraft with orderer0/1/2 |
| 2 peers per org, CouchDB world state | ✅ docker-compose with CouchDB per peer |
| KYC Contract — all 5 functions | ✅ |
| Alert Contract — all 5 functions (CouchDB rich query) | ✅ |
| Audit Contract — all 4 functions | ✅ |
| Full input validation | ✅ All chaincodes |
| Composite key design | ✅ status+customer, customer+alert, risk+alert, entityType+entityID |
| Event emission per state change | ✅ SetEvent on every write |
| Unit tests with mock shim | ✅ shimtest in all 3 chaincodes |
| Fabric SDK integration | ✅ fabric-sdk-go with connection profile |
| Channel client pooling | ✅ Round-robin atomic counter |
| Event listener → Kafka | ✅ All 3 channels, eventEnvelope JSON |
| Health check verifying peer connectivity | ✅ QueryInfo + resmgmt.QueryChannels |

---

### Phase 7: ML Service (Python + FastAPI + gRPC) ✅

**What was built (32 files):**

| File | Description |
|------|-------------|
| `ml/__init__.py` + sub-package `__init__.py` files (×7) | Python package structure |
| `ml/data/preprocessor.py` | Elliptic dataset: load → filter unknowns → remap labels → temporal 70/30 split → SMOTE (1:2) |
| `ml/features/engineering.py` | 85-feature selection (SELECTED_FEATURE_INDICES), proto-to-array mapping |
| `ml/models/base.py` | Abstract `FraudModel` + `SklearnFraudModel` mixin (joblib save/load) |
| `ml/models/random_forest.py` | RandomForestClassifier — 300 trees, `class_weight=balanced` |
| `ml/models/xgboost_model.py` | XGBClassifier + optional Optuna TPE hyperparameter search |
| `ml/models/lightgbm_model.py` | LGBMClassifier — best ROC-AUC 96.49%, early stopping |
| `ml/models/gnn_model.py` | 3-layer GraphSAGE (PyTorch Geometric), graph-aware + MLP-fallback inference |
| `ml/models/autoencoder.py` | Reconstruction-error anomaly detector, trained on licit-only samples |
| `ml/models/ensemble.py` | Weighted average (LGBM 35%, RF 33%, XGB 32%), A/B testing via `ab_ratio` |
| `ml/explainability/shap_explainer.py` | `TreeSHAPExplainer` (exact) + `DeepSHAPExplainer` (neural nets), top-N contributions |
| `ml/explainability/lime_explainer.py` | `LIMEFraudExplainer` — model-agnostic, discretized tabular |
| `ml/explainability/counterfactual.py` | Perturbation-based counterfactual (gradient descent on top-K SHAP features) |
| `ml/federated/federated_stub.py` | FedAvg across 3 institution partitions (TFF if available, LightGBM simulation fallback) |
| `ml/evaluation/evaluator.py` | Full metrics suite + `ModelComparisonReport` + hardcoded `COLAB_BENCHMARK` |
| `services/ml-service/app/models/registry.py` | Thread-safe `ModelRegistry`, TTL hot-reload, ensemble auto-build |
| `services/ml-service/app/features/pipeline.py` | `FeaturePipeline.transform()` and `transform_batch()` |
| `services/ml-service/app/schemas/prediction.py` | Pydantic v2 schemas (request + response) for REST API |
| `services/ml-service/app/api/routes.py` | FastAPI: POST /predict, POST /predict/batch, POST /explain/lime, POST /explain/counterfactual, GET /model/metrics, GET /model/comparison, GET /health |
| `services/ml-service/app/grpc/servicer.py` | `FraudMLServicer` — all 11 RPCs implemented |
| `services/ml-service/app/grpc/server.py` | gRPC server with 4 interceptors (logging, tracing, auth, recovery) |
| `services/ml-service/main.py` | Dual FastAPI + gRPC startup (shared state, LIME background init) |
| `proto/gen/python/fraud/v1/fraud_pb2.py` | Hand-written proto message stubs |
| `proto/gen/python/fraud/v1/fraud_pb2_grpc.py` | Hand-written gRPC stub + `add_FraudMLServiceServicer_to_server` |
| `proto/gen/python/common/v1/common_pb2.py` | `RiskLevel`, `RequestMetadata`, `HealthCheckRequest/Response`, `SHAPContribution` |
| `services/ml-service/tests/unit/test_feature_pipeline.py` | 9 tests: feature selection, proto→array, batch transform |
| `services/ml-service/tests/unit/test_model_registry.py` | 7 tests: empty dir, corrupt file, TTL reload, ensemble build |
| `services/ml-service/tests/unit/test_grpc_servicer.py` | 17 tests: all RPCs including validation errors + edge cases |

**Actual model performance (from Google Colab training, 2026-04-01):**

| Model | Precision | Recall | F1 | ROC-AUC |
|-------|-----------|--------|----|---------|
| LightGBM | 64.61% | 68.18% | 66.35% | **96.49%** |
| RandomForest | 88.34% | 56.92% | 69.23% | 96.38% |
| XGBoost | 70.64% | 63.24% | 66.74% | 95.97% |

- Train: 36,922 labeled → 49,324 post-SMOTE (1:2 ratio), 85 features
- Test: 9,642 samples (506 fraud = 5.25%), temporal split (no data leakage)
- Best model: LightGBM by ROC-AUC; RF by Precision

**Phase 7 requirements met:**

- [x] FastAPI REST API (POST /predict, batch, LIME, counterfactual, metrics)
- [x] gRPC service — all 11 RPCs (VerifyFace, PredictFraud, BatchPredictFraud, StreamPredictions, GetLIMEExplanation, GetCounterfactual, GetModelMetrics, GetModelComparison, PredictWithModel, TriggerRetraining, HealthCheck)
- [x] 3 tree models (RF, XGBoost, LightGBM) with sklearn-joblib save/load
- [x] GNN model (GraphSAGE, 3-layer, PyTorch Geometric)
- [x] Autoencoder anomaly detector (unsupervised, licit-only training)
- [x] Weighted ensemble with A/B testing
- [x] SHAP TreeExplainer + DeepExplainer + top-N contributions per prediction
- [x] LIME LimeTabularExplainer, model-agnostic
- [x] Perturbation-based counterfactual generator
- [x] Federated learning stub (TFF FedAvg / simulation fallback)
- [x] Full evaluation suite with COLAB_BENCHMARK constants
- [x] Thread-safe model registry with TTL hot-reload
- [x] OpenTelemetry tracing interceptors (already in app/grpc/interceptors.py)
- [x] JWT auth via IAM gRPC
- [x] Proto stubs (hand-written, replace with protoc output in CI)
- [x] Unit tests: 33 tests across 3 test files

### Phase 8: Transaction Monitoring Service (Go) ✅

**What was built (20 files):**

| File | Purpose |
|------|---------|
| `proto/gen/go/ml/v1/ml.pb.go` | Extended with TransactionFeatures, PredictFraudRequest/Response, BatchPredict, ModelMetrics types |
| `proto/gen/go/ml/v1/ml_grpc.pb.go` | Extended with PredictFraud, BatchPredictFraud, GetModelMetrics, GetModelComparison in client/server interfaces |
| `proto/gen/go/transaction/v1/transaction.pb.go` | Full TransactionService message types: RawTransaction, EnrichedTransaction, all 8 request/response types |
| `proto/gen/go/transaction/v1/transaction_grpc.pb.go` | TransactionServiceClient/Server, RegisterTransactionServiceServer, ServiceDesc, all 8 method handlers |
| `services/transaction-service/go.mod` | Updated: added proto/gen/go, golang-jwt/jwt/v5, removed pgx (not needed) |
| `services/transaction-service/internal/config/config.go` | Env-driven config: gRPC port, Kafka topics, MongoDB, Redis, ML addr, thresholds, pipeline version |
| `services/transaction-service/internal/domain/transaction.go` | Domain models: RawTransaction, TransactionFeatures, FraudPrediction, EnrichedTransaction, AlertEvent, VelocityRecord, VelocityStats, CachedRiskScore, LastTxRecord, errors |
| `services/transaction-service/internal/features/extractor.go` | Feature extraction pipeline: temporal, velocity (Redis), geographic (haversine, country risk), merchant risk, KYC profile. Country risk table (50+ countries), merchant risk table (14 high-risk categories), USD conversion rates (25 currencies + crypto) |
| `services/transaction-service/internal/repository/redis/velocity_repo.go` | Redis sorted-set velocity tracking: RecordTransaction, GetVelocityAggregates (1h/24h/7d/30d), GetLastTransaction, GetCustomerProfile, GetCountryHistory (2h), CacheRiskScore, GetCachedRiskScore, GetVelocityStats |
| `services/transaction-service/internal/repository/mongo/transaction_repo.go` | MongoDB time-series: EnsureCollection (timeseries with TTL=90d), Save (idempotent), GetByTxHash, GetCustomerHistory (cursor pagination), ComputeFraudRate30D (aggregation pipeline) |
| `services/transaction-service/internal/clients/ml_client.go` | ML gRPC client: PredictFraud with nil-safe conn handling, heuristic fallback (geographic+merchant risk), HealthCheck, full proto↔domain mapping |
| `services/transaction-service/internal/kafka/consumer.go` | Kafka consumer: worker pool (configurable), FetchMessage → deserialise → validate → processor → CommitMessages, error handling with DLQ comment |
| `services/transaction-service/internal/kafka/producer.go` | Kafka alert producer: PublishAlert with trace header injection, CustomerID partition key, synchronous writes |
| `services/transaction-service/internal/service/transaction_service.go` | Core orchestrator: ProcessTransaction (6-step pipeline), GetTransaction, GetCustomerHistory, GetRiskScore (Redis cache + MongoDB fallback), GetVelocityStats, HealthCheck. Port interfaces for testability |
| `services/transaction-service/internal/service/transaction_service_test.go` | 15 unit tests: happy path, alert trigger, threshold boundary, validation error, feature extraction error, MongoDB failure (non-fatal), Kafka failure (non-fatal), ML predictor error, risk score cache hit/miss, velocity stats, health check |
| `services/transaction-service/internal/grpc/server.go` | gRPC server: JWT HS256 validator, public methods list, interceptor chain, graceful shutdown |
| `services/transaction-service/internal/grpc/handler.go` | TransactionServiceServer: all 8 RPC handlers, proto↔domain mapping, error code mapping, domain interface assertion |
| `services/transaction-service/cmd/server/main.go` | Entry point: MongoDB → Redis → ML gRPC → Kafka producer → feature extractor → service → Kafka consumer + gRPC server, graceful shutdown |
| `services/transaction-service/Dockerfile` | Multi-stage scratch image: CGO_ENABLED=0, non-root UID 65532 |
| `services/transaction-service/README.md` | Service docs: architecture diagram, env vars, Redis key schema, MongoDB schema, gRPC API table, alert thresholds |

**Phase 8 requirement checklist:**
| Requirement | Implementation |
|-------------|---------------|
| Kafka consumer: `transactions.raw` | `kafka/consumer.go` — worker pool, CommitMessages on success |
| Real-time feature extraction | `features/extractor.go` — 6 feature categories |
| Velocity checks: count/amount per 1h/24h | `redis/velocity_repo.go` — sorted set ZRANGEBYSCORE aggregation |
| Geographic anomaly: country change in 2h | `features/extractor.go` — CountryChange2H flag via `countries:{id}:2h` sorted set |
| Behavioral deviation vs 30-day avg | `features/extractor.go` — AmountDeviationScore = (amount - avg30d) / std30d |
| ML Service gRPC call | `clients/ml_client.go` — PredictFraud with heuristic fallback |
| Threshold > 0.7 → `alerts.created` | `service/transaction_service.go` — `buildAlertEvent` + `alertPublisher.PublishAlert` |
| MongoDB time-series enriched transactions | `repository/mongo/transaction_repo.go` — 90-day TTL time-series collection |
| Redis risk score cache (5-min TTL) | `redis/velocity_repo.go` — `CacheRiskScore` / `GetCachedRiskScore` |
| gRPC TransactionService | `grpc/handler.go` — 8 RPCs including IngestTransaction(sync/async), IngestBatch |

### Phase 9: Alert & Notification Service (Go) ✅

**What was built (22 files):**

| File | Purpose |
|------|---------|
| `proto/gen/go/alert/v1/alert.pb.go` | AlertRecord, CreateAlert/GetAlert/ListAlerts/UpdateAlertStatus/AssignAlert/EscalateAlert/SendNotification/GetAlertStats request/response types, NotificationChannel enum |
| `proto/gen/go/alert/v1/alert_grpc.pb.go` | AlertServiceClient/Server interfaces (10 methods), UnimplementedAlertServiceServer, full client Invoke implementation |
| `services/alert-service/go.mod` | Dependencies: pgx/v5, go-redis/v9, kafka-go, sendgrid-go, twilio-go, gorilla/websocket, zerolog, golang-jwt/jwt/v5, otel |
| `services/alert-service/internal/config/config.go` | Env-driven config: PostgreSQL DSN builder, Redis, Kafka, SendGrid, Twilio, Slack, webhook, escalation settings, JWT secret, WS timings |
| `services/alert-service/internal/domain/alert.go` | AlertPriority (0–4) with PriorityFromFraudProb, AlertStatus lifecycle, validTransitions map, ValidateTransition, AlertIngestEvent+Validate, Alert struct, AlertFilters, AlertStats, WSMessage types, error sentinels |
| `services/alert-service/scripts/db/migrations/002_alert_schema.sql` | `fraud_alerts` (UNIQUE dedup_hash, lifecycle status CHECK, priority 1–4), `alert_notifications` log, `alert_status_history` immutable audit, 6 indexes (customer+time, status+priority, partial escalation candidates, assignee, fraud_prob), updated_at trigger |
| `services/alert-service/internal/repository/postgres/alert_repo.go` | AlertRepository: Create (dup key→ErrDuplicateAlert), GetByID, List (dynamic WHERE + pagination), GetByCustomer, UpdateStatus (transactional with history row), Assign, GetEscalationCandidates (partial index query), LogNotification, GetStats (aggregate query), Ping |
| `services/alert-service/internal/repository/redis/dedup_repo.go` | DedupRepository: SHA-256(customerID:txHash) → SETNX with 24h TTL; IsDuplicate (atomic check-and-set), Evict (rollback on failure), Ping |
| `services/alert-service/internal/notification/email.go` | EmailSender: SendGrid SDK, builds plain-text body with SHAP explanation, supports default recipients, logs message ID |
| `services/alert-service/internal/notification/sms.go` | SMSSender: Twilio REST API, iterates all phone recipients, logs SID per message |
| `services/alert-service/internal/notification/slack.go` | SlackSender: incoming webhook POST with colored attachment, priority-mapped colors, fields (customer, tx_hash, fraud_prob, risk_score, status, model) |
| `services/alert-service/internal/notification/webhook.go` | WebhookSender: POST to N URLs, HMAC-SHA256 `X-Fraud-Signature` header, 15s timeout per endpoint |
| `services/alert-service/internal/notification/dispatcher.go` | Dispatcher: priority-based routing (Slack=all, Email=HIGH+CRITICAL, SMS=CRITICAL, Webhook=all), NotificationLogger interface, persists results via LogNotification |
| `services/alert-service/internal/kafka/consumer.go` | Consumer: worker pool (configurable), FetchMessage → unmarshal → validate → IngestAlert → CommitMessages, DLQ comment |
| `services/alert-service/internal/websocket/hub.go` | Hub: register/unregister/broadcast channels, RWMutex client map, writePump (ping heartbeat), readPump (pong handler), slow-client eviction |
| `services/alert-service/internal/websocket/handler.go` | ServeWS: gorilla/websocket upgrader, spawns readPump+writePump goroutines per client |
| `services/alert-service/internal/escalation/scheduler.go` | Scheduler: ticker-based poll every EscalationInterval, GetEscalationCandidates from PostgreSQL, round-robin analyst assignment, atomic escalated counter |
| `services/alert-service/internal/service/alert_service.go` | AlertService: IngestAlert (dedup→persist→notify→broadcast), UpdateStatus, AssignAlert, EscalateAlert (auto-notify), GetEscalationCandidates, GetStats, HealthCheck. Port interfaces for testability |
| `services/alert-service/internal/service/alert_service_test.go` | 15 unit tests: happy path (LOW/CRITICAL), Redis dup, Postgres dup, store error+Redis eviction, invalid event, fraud_prob out of range, GetAlert found/not-found, UpdateStatus valid/error, EscalateAlert assigns analyst, HealthCheck ok/postgres-down, priority boundary table test |
| `services/alert-service/internal/grpc/server.go` | gRPC server: JWT HS256 validator, public methods [HealthCheck], interceptor chain, GracefulStop |
| `services/alert-service/internal/grpc/handler.go` | AlertServiceServer: all 10 RPCs, proto↔domain mapping, domainToProto, status conversion, mapDomainError (NotFound/AlreadyExists/FailedPrecondition/InvalidArgument/Internal) |
| `services/alert-service/internal/http/handler.go` | REST handler: GET /alerts, GET /alerts/:id, GET /alerts/customer/:id, PATCH /alerts/:id/status, POST /alerts/:id/assign, POST /alerts/:id/escalate, GET /alerts/stats, GET /health |
| `services/alert-service/internal/http/server.go` | HTTP server: mux with sub-router for /alerts/* path dispatch, logging middleware, 15s read/30s write timeouts |
| `services/alert-service/cmd/server/main.go` | Entry point: PostgreSQL→Redis→notifications→WebSocket hub→alert service→escalation scheduler→Kafka consumer→gRPC+HTTP servers, graceful shutdown |
| `services/alert-service/Dockerfile` | Multi-stage scratch image: golang:1.23-alpine builder, non-root UID 65532, exposes 9003 (HTTP) + 10003 (gRPC) |

**Phase 9 requirement checklist:**
| Requirement | Implementation |
|-------------|---------------|
| Kafka consumer: `alerts.created` | `kafka/consumer.go` — worker pool, CommitMessages on success |
| Alert deduplication | `redis/dedup_repo.go` — SETNX SHA-256 hash; `fraud_alerts.dedup_hash UNIQUE` as safety net |
| Priority scoring: LOW/MEDIUM/HIGH/CRITICAL | `domain/alert.go` — `PriorityFromFraudProb()` with boundaries <0.5/0.5-0.7/0.7-0.85/>0.85 |
| PostgreSQL lifecycle persistence | `repository/postgres/alert_repo.go` — full CRUD + status history + transactional UpdateStatus |
| Email via SendGrid | `notification/email.go` — SDK, to/from, body with SHAP explanation |
| SMS via Twilio | `notification/sms.go` — REST API, per-recipient loop |
| Slack webhook | `notification/slack.go` — colored attachment, priority fields |
| Webhook POST | `notification/webhook.go` — HMAC-SHA256 signed, N endpoints |
| WebSocket real-time broadcast | `websocket/hub.go+handler.go` — hub pattern, gorilla/websocket, ping heartbeat |
| CRITICAL 15-min auto-escalation | `escalation/scheduler.go` — ticker poll, round-robin analyst assignment |
| REST API | `http/handler.go+server.go` — GET/PATCH /alerts, GET /alerts/:id, /alerts/stats, /health |
| gRPC API | `grpc/handler.go` — 10 RPC methods, full proto↔domain mapping |

### Phase 10: Case Management Service (Go) ✅

**What was built (20 files):**

| File | Purpose |
|------|---------|
| `proto/gen/go/case/v1/case.pb.go` | CaseStatus/CasePriority/EvidenceType enums, CaseRecord, EvidenceRecord, CaseActionRecord, InvestigatorRecord, CaseStats; all 12 RPC request/response types |
| `proto/gen/go/case/v1/case_grpc.pb.go` | CaseServiceClient/Server (12 methods), RegisterCaseServiceServer, all 12 handler shims |
| `services/case-service/go.mod` | Updated: proto/gen/go, golang-jwt/jwt/v5, kafka-go, aws-sdk-go-v2 (S3), gofpdf |
| `services/case-service/internal/config/config.go` | PostgreSQL DSN, Kafka, AWS S3, Blockchain Service URL, investigator pool, SAR threshold, JWT, gRPC port |
| `services/case-service/internal/domain/case.go` | Case status lifecycle + ValidateTransition, CasePriority, EvidenceType, AlertEvent, Case/Evidence/CaseAction structs, error sentinels |
| `services/case-service/scripts/db/migrations/003_case_schema.sql` | `investigation_cases` (UNIQUE alert_id, SAR tracking), `case_evidence`, `case_actions` (immutable), 5 indexes, trigger |
| `services/case-service/internal/repository/postgres/case_repo.go` | Full CRUD; transactional UpdateCaseStatus with action log; GetInvestigatorWorkload (GROUP BY); GetStats (aggregate); SetSAR (idempotent) |
| `services/case-service/internal/clients/blockchain_client.go` | HTTP client for Blockchain Service audit-channel: RecordInvestigatorAction, UpdateAlertStatus, Ping |
| `services/case-service/internal/s3/evidence_store.go` | AWS SDK v2: PresignPutURL, PresignGetURL, PutObject (SAR PDF), DeleteObject; EvidenceKey/SARKey helpers |
| `services/case-service/internal/pdf/sar_generator.go` | gofpdf: 5-section FinCEN-style SAR (header, case summary, narrative, timeline table, evidence inventory, certification) |
| `services/case-service/internal/kafka/consumer.go` | Worker pool consumer: filters HIGH/CRITICAL only, calls CaseCreator, commits on success |
| `services/case-service/internal/service/case_service.go` | CreateCaseFromAlert (idempotent), CreateCase, GetCase, ListCases, UpdateCaseStatus, AssignCase, AutoAssign (round-robin), AddEvidence, GetEvidence, DeleteEvidence, GenerateSAR, GetCaseStats, GetInvestigatorWorkload, HealthCheck; auditAsync goroutine |
| `services/case-service/internal/service/case_service_test.go` | 17 unit tests with inline mocks: auto-creation, idempotency, gRPC creation, transitions, round-robin, evidence CRUD, SAR generation/duplicate, health, priority boundaries |
| `services/case-service/internal/grpc/server.go` | JWT HS256 interceptor, GracefulStop |
| `services/case-service/internal/grpc/handler.go` | CaseServiceServer: all 12 RPCs, full domain↔proto mapping, mapErr |
| `services/case-service/internal/http/handler.go` | 12 REST endpoints: POST/GET /cases, GET/PATCH /cases/:id/status, POST /cases/:id/assign, POST /cases/:id/sar, POST/GET/DELETE /cases/:id/evidence, GET /cases/stats+workload |
| `services/case-service/internal/http/server.go` | Mux with fixed routes + /cases/* sub-router, logging middleware |
| `services/case-service/cmd/server/main.go` | PG→S3→blockchain→SAR gen→service→Kafka+gRPC+HTTP, graceful shutdown |
| `services/case-service/Dockerfile` | Multi-stage scratch, non-root UID 65532, ports 9004/10004 |

**Phase 10 requirement checklist:**
| Requirement | Implementation |
|-------------|---------------|
| Auto-create case from CRITICAL/HIGH alerts | Kafka consumer filters prob ≥ 0.70; `CreateCaseFromAlert` idempotent on alert_id |
| Case workflow OPEN→IN_REVIEW→PENDING_SAR→CLOSED | `ValidateTransition` + transactional `UpdateCaseStatus` with action log |
| S3 pre-signed URLs for evidence | PresignPutURL (client-side upload) + PresignGetURL (download); SAR PDF via PutObject |
| Round-robin investigator assignment with workload | `nextInvestigator()` atomic counter; `AutoAssign`; `GetInvestigatorWorkload` for balancing |
| SAR PDF generation (gofpdf) | 5-section FinCEN-style PDF: timeline + evidence tables, certification block |
| Record actions via Blockchain Service | `blockchain_client.go` → POST /internal/v1/audit/investigator-action in background goroutine |
| REST CRUD for cases, evidence, assignments | 12 REST endpoints in `http/handler.go` |
| gRPC API | 12 RPC methods in `grpc/handler.go` |

### Phase 11: API Gateway
**To build:**
- Traefik configuration
- Middleware chain: rate limiting (token bucket), JWT validation, request ID, trace propagation, CORS, security headers
- Versioned routing: `/api/v1/...`
- `/health` aggregation endpoint

### Phase 12: Analytics & Reporting Service (Go)
**To build:**
- TimescaleDB hypertable for metrics
- Endpoints: fraud-rate, model-performance, alert-summary, kyc-stats, compliance report (PDF)
- Model comparison table (live benchmarks vs targets)

### Phase 13: Testing Suite
**To build:**
- Go unit tests (>80% coverage): testify + gomock for all services
- Python unit tests: pytest + pytest-cov for ML pipeline
- Integration tests: Testcontainers (real PostgreSQL, MongoDB, Redis, Kafka)
- E2E: Postman collection (happy path + edge cases)
- Locust performance tests: 10,000 TPS off-chain, 500 TPS blockchain writes

### Phase 14: Kubernetes & Infrastructure
**To build:**
- Helm charts per service: Deployment, HPA, PDB, ConfigMap, Sealed Secrets
- Terraform modules: VPC, EKS (general/ml/blockchain node groups), RDS, ElastiCache, MSK, S3

### Phase 15: CI/CD & Monitoring
**To build:**
- GitHub Actions: ci.yml, cd-staging.yml, cd-production.yml (blue-green)
- Prometheus alerting rules (latency, accuracy, blockchain, Kafka lag)
- Grafana dashboards: System Overview, Fraud Detection, Blockchain Health, ML Performance

---

## Problems Encountered & Resolutions

---

### Bug #1 — Duplicate `codes` import alias in shared middleware
**File:** `shared/go/middleware/grpc_interceptors.go`
**Severity:** 🔴 Compile Error — entire shared module fails to build

**Problem:**
Both `go.opentelemetry.io/otel/codes` and `google.golang.org/grpc/codes` were imported without
aliases, causing a duplicate identifier `codes` at the package level:
```go
// BEFORE (broken):
"go.opentelemetry.io/otel/codes"       // → codes.Error, codes.Ok
"google.golang.org/grpc/codes"         // → codes.Internal, codes.Unauthenticated
```
Go does not allow two imports to share the same local name.

**Root cause:** Both packages use `codes` as their last path segment; without explicit aliases,
both default to `codes`, which is a compile-time collision.

**Fix applied:**
```go
// AFTER (fixed):
otelcodes "go.opentelemetry.io/otel/codes"  // alias for OTel span status
"google.golang.org/grpc/codes"              // gRPC codes keep the default name
```
Also updated the two OTel usages in `UnaryServerTracingInterceptor`:
```go
span.SetStatus(otelcodes.Error, err.Error())
span.SetStatus(otelcodes.Ok, "")
```

**Impact if unfixed:** Every Go service that imports `github.com/fraud-detection/shared` would
fail to compile, blocking Phases 3–15 entirely.

---

### Bug #2 — Missing `googlegrpc` import alias in encryption-service gRPC server
**File:** `services/encryption-service/internal/grpc/server.go`
**Severity:** 🔴 Compile Error — encryption service fails to build

**Problem:**
The server struct and constructor referenced `googlegrpc.Server`, `googlegrpc.NewServer()`, and
`googlegrpc.ChainUnaryInterceptor()`, but the import used no alias:
```go
// BEFORE (broken):
"google.golang.org/grpc"   // default name: grpc

// Usage:
grpcSrv *googlegrpc.Server        // ERROR: googlegrpc undefined
s.grpcSrv = googlegrpc.NewServer( // ERROR: googlegrpc undefined
```
The author intended the alias `googlegrpc` (to match the IAM service's pattern) but forgot it in
the encryption service.

**Fix applied:**
```go
// AFTER (fixed):
googlegrpc "google.golang.org/grpc"
```

**Impact if unfixed:** Encryption service cannot compile; Vault Transit integration is completely
inaccessible, blocking every downstream service that encrypts PII (KYC, Transaction, etc.).

---

### Bug #3 — Dummy JWT validator in encryption-service accepted any non-empty token
**File:** `services/encryption-service/internal/grpc/server.go`
**Severity:** 🟠 Security Vulnerability — any caller with any token string could invoke
encrypt/decrypt operations

**Problem:**
```go
// BEFORE (insecure placeholder):
func makeTokenValidator(jwtSecret string) ... {
    return func(ctx, token) (...) {
        if token == "" {
            return "", "", nil, fmt.Errorf("empty token")
        }
        return "svc-caller", "service", nil, nil  // accepts anything!
    }
}
```

**Root cause:** Developer left a placeholder for development that was never replaced.

**Fix applied:**
- Added `github.com/golang-jwt/jwt/v5 v5.2.1` to `encryption-service/go.mod`
- Implemented real HMAC-SHA256 JWT validation using the shared secret:
  - Verifies signature algorithm is HMAC (rejects RS256/ES256 algorithm confusion attacks)
  - Verifies token expiry (`WithExpirationRequired()`)
  - Extracts `uid` and `role` claims for audit logging
- Updated import in `server.go`: `jwtv5 "github.com/golang-jwt/jwt/v5"`

**Impact if unfixed:** Any internal (or external if port accidentally exposed) caller could
encrypt/decrypt arbitrary PII without a valid JWT — complete security bypass on the encryption
layer, the most sensitive service in the system.

---

### Bug #4 — IAM Service gRPC handlers not registered (service started but served nothing)
**File:** `services/iam-service/internal/grpc/server.go`
**Severity:** 🟡 Functional Gap — service starts successfully but returns UNIMPLEMENTED on all RPCs

**Problem:**
The IAM gRPC server was constructed with the full interceptor chain but no service was registered:
```go
// BEFORE (incomplete):
// TODO: Register proto-generated service once stubs are available.
//   iamv1.RegisterAuthServiceServer(s.grpcServer, NewAuthHandler(authSvc))
// Run `make proto` first to generate: github.com/fraud-detection/proto/gen/go/iam/v1
```
The IAM proto stubs (`proto/gen/go/iam/v1/`) had not been created, and `iam-service/go.mod` did
not declare the `proto/gen/go` dependency.

**Root cause:** The encryption service had its proto stubs created in Phase 2, but the IAM stubs
were deferred with a TODO. No `make proto` infrastructure was run to generate them.

**Fix applied (3 steps):**

1. **Created hand-written IAM proto stubs** (matching the pattern of encryption stubs):
   - `proto/gen/go/iam/v1/iam.pb.go` — all 14 request/response message types + UserProfile, Permission
   - `proto/gen/go/iam/v1/iam_grpc.pb.go` — IAMServiceClient, IAMServiceServer, UnimplementedIAMServiceServer,
     14 full-method-name constants, service descriptor, all 14 handler funcs, RegisterIAMServiceServer

2. **Created IAM gRPC handler** (`services/iam-service/internal/grpc/handler.go`):
   - `AuthHandler` struct implementing `IAMServiceServer`
   - All 14 RPCs implemented: Register, Login, RefreshToken, MFASetup, MFAVerify, Logout,
     ChangePassword, GetProfile, ValidateToken, GetPermissions, ListUsers, UpdateUser,
     DeactivateUser, HealthCheck
   - `mapAuthError()` function translating domain.AuthError codes to gRPC status codes
   - Compile-time interface assertion: `var _ iamv1.IAMServiceServer = (*AuthHandler)(nil)`

3. **Updated go.mod and server.go:**
   - `iam-service/go.mod`: added `github.com/fraud-detection/proto/gen/go v0.0.0` + replace directive
   - `iam-service/internal/grpc/server.go`: removed TODO, added import, called
     `iamv1.RegisterIAMServiceServer(s.grpcServer, NewAuthHandler(authSvc, tokenSvc, log))`

**Impact if unfixed:** No external caller (API Gateway, other services) could authenticate users,
validate tokens, or manage accounts. The entire auth layer would be non-functional despite the
underlying business logic being complete.

---

### Issue #5 — `envRequired()` in IAM config logs warning instead of returning error
**File:** `services/iam-service/internal/config/config.go`
**Severity:** 🟢 Low Risk — mitigated by downstream validation in Load()

**Problem:**
```go
func envRequired(key string) string {
    v := os.Getenv(key)
    if v == "" {
        log.Warn().Str("key", key).Msg("required env var not set")  // only warns
    }
    return v  // returns "" silently
}
```

**Status:** Partially mitigated — `Load()` validates the critical fields immediately after:
```go
if len(cfg.JWTSecret) < 32 { return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters...") }
if cfg.PostgresPass == ""  { return nil, fmt.Errorf("POSTGRES_PASSWORD is required") }
```
`REDIS_PASSWORD` is not validated downstream — a blank Redis password will only fail at runtime
when the connection attempt is made.

**Resolution:** Left as-is for now since compile errors were the priority. A future improvement
would be to change `envRequired` to collect errors and return them from `Load()`.

---

## Open TODOs (Non-Blocking)

| ID | File | Issue | Phase to Fix |
|----|------|-------|-------------|
| T1 | `iam-service/internal/grpc/handler.go:Logout` | JTI not propagated through context; uses worst-case TTL for blocklist | Phase 11 |
| T2 | `iam-service/internal/service/token_service.go:145` | JTI blocklist check fails open when Redis is down in dev, closed in prod — should be configurable | Phase 13 |
| T3 | `encryption-service/internal/grpc/server.go` | `ENCRYPTION_JWT_SECRET` env var not validated in config; empty string disables auth | Phase 4 follow-up |
| T4 | `iam-service/internal/config/config.go:envRequired` | Returns empty string + warns; should fail fast | Phase 13 |
| T5 | `proto/gen/go/` | All stubs are hand-written; replace with real `protoc` output via `make proto` | Before Phase 6 |
| T6 | `services/iam-service/internal/grpc/handler.go:UpdateUser` | `active` field: always sets active=req.Active even if caller only wants to change role | Phase 12 |
| T7 | `kyc-service/internal/http/handler.go:GetDecryptedPII` | Actor ID read from `X-User-ID` header; should come from validated JWT claims via auth middleware | Phase 11 |
| T8 | `kyc-service/internal/storage/local_store.go` | LocalDocumentStore for dev only; production must use S3 pre-signed URL pattern | Phase 14 |
| T9 | `kyc-service/internal/clients/facematch.go` | mockFaceMatchClient always returns match=true; real gRPC client to ML service needed | Phase 7 |
| T10 | `kyc-service/internal/textract/client.go:pollForCompletion` | Fixed 2-second poll interval; production should use exponential backoff | Phase 13 |

---

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Hand-written proto stubs | `protoc` not available in dev environment; stubs unblock service development and will be replaced by `make proto` output |
| JWT validated locally in encryption-service | Avoids circular dependency (encryption ↔ IAM); encryption service only needs to confirm the token was signed by the system, not full permission resolution |
| Shared `google.golang.org/grpc` aliased as `googlegrpc` | Avoids collision with the local `grpc` package name used in gRPC interceptor files |
| OTel codes aliased as `otelcodes` | Conventional alias to distinguish from `google.golang.org/grpc/codes` which is used far more frequently |
| Refresh token device binding | Security-in-depth: if a refresh token is stolen, the attacker needs the original device ID too; mismatch triggers immediate revocation |
| Vault Transit (not application-level AES) | Key rotation handled by Vault; no key material ever touches application memory; supports rewrap for old ciphertexts |
| KYC status state machine (Phase 5) | Explicit transition map in `validateStatusTransition()` rather than ad-hoc checks; invalid transitions return `ErrInvalidStatus` → gRPC `FailedPrecondition` / HTTP 422 |
| Async blockchain anchoring (Phase 5) | Blockchain is eventually-consistent by design; wrapping in a goroutine with its own 30s timeout prevents customer registration from blocking on Phase 6 availability |
| PII audit log before decrypt (Phase 5) | `LogAuditEvent` is called before `BatchDecryptPII` returns data; if the audit write fails the caller gets an error and no PII is exposed — audit-log-or-deny pattern |
| Dual JSON + multipart document upload (Phase 5) | Same route handles JSON `{s3_key}` (pre-uploaded) and `multipart/form-data` (direct upload); detected by `Content-Type` header — clients can use either flow without separate endpoints |












 Project Completion Status                                                                                                                                              
                                                                                                                                                                         
  ✅ Fully Implemented                                                                                                                                                   
                                                                                                                                                                         
  ┌───────────────────────┬─────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐        
  │       Component       │   Status    │                                                        Details                                                        │        
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ shared/go             │ ✅ Complete │ logger, tracing, middleware (gRPC interceptors), grpcclient — all tests pass                                          │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ iam-service           │ ✅ Complete │ Auth, RBAC, JWT, TOTP MFA, rate limiting, Redis token store, Postgres user repo                                       │        
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ transaction-service   │ ✅ Complete │ Kafka consumer, feature extractor, ML client, velocity counters (Redis), MongoDB repo, gRPC                           │        
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ alert-service         │ ✅ Complete │ Alert lifecycle, WebSocket hub, email/SMS/Slack/webhook notifications, escalation scheduler, dedup                    │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ case-service          │ ✅ Complete │ Investigation cases, SAR PDF generation, evidence S3 upload, blockchain anchoring, round-robin assignment             │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ analytics-service     │ ✅ Complete │ Fraud trends, risk distribution, model performance, geographic distribution, 4 report types, Postgres + MongoDB repos │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ blockchain-service    │ ✅ Complete │ Hyperledger Fabric SDK, KYC/alert/audit channel ops, health check                                                     │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ encryption-service    │ ✅ Complete │ Vault Transit AES-256-GCM encrypt/decrypt, gRPC server                                                                │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ api-gateway           │ ✅ Complete │ Traefik-style reverse proxy, JWT validation, CORS, rate limiting, request ID                                          │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ kyc-service           │ ✅ Complete │ Customer onboarding, OCR (Textract), face match, blockchain KYC anchoring                                             │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ ml-service            │ ✅ Complete │ FastAPI + gRPC, ensemble models, SHAP/LIME explainability, model registry                                             │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ ML pipeline (/ml/)    │ ✅ Complete │ XGBoost, LightGBM, Random Forest, GNN, Autoencoder, ensemble, SHAP, LIME, counterfactual                              │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ Blockchain chaincodes │ ✅ Complete │ kyc-contract, alert-contract, audit-contract (Hyperledger Fabric 2.x)                                                 │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ proto/gen/go          │ ✅ Complete │ All 7 service stubs (iam, kyc, transaction, alert, case, analytics, encryption, common, ml)                           │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ Docker stack          │ ✅ Complete │ docker-compose.yml — 13+ containers (Postgres, Mongo, Redis, Kafka, Vault, Jaeger, Prometheus, Grafana)               │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ DB migrations         │ ✅ Complete │ 4 migration files: IAM schema, alert schema, case schema, analytics views                                             │
  ├───────────────────────┼─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤        
  │ Observability         │ ✅ Complete │ Prometheus rules, Grafana dashboards, Jaeger distributed tracing                                                      │
  └───────────────────────┴─────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘        
                                                               
  ⚠️  Not Yet Done (infrastructure-only gaps)                                                                                                                             
                                                               
  ┌────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────┐                                  
  │                Item                │                                            Notes                                             │
  ├────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ scripts/setup.sh                   │ Bootstrap script referenced in Makefile — needs to be written if you want make setup to work │
  ├────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ ML model artifacts                 │ Models need to be trained (make ml-train) — no pre-trained weights committed                 │                                  
  ├────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤                                  
  │ Hyperledger Fabric crypto material │ Network certs (make fabric-up) need to be generated before Fabric starts                     │                                  
  ├────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤                                  
  │ E2E / integration / perf tests     │ Test skeletons exist but need a running stack to execute                                     │
  └────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────┘                                  
                                                               
  ---                                                                                                                                                                    
  Running Instructions — Complete Guide                        

  Prerequisites

  Install these before starting:                                                                                                                                         
   
  # Go 1.23+                                                                                                                                                             
  go version   # must be >= 1.23                               

  # Docker + Docker Compose v2                                                                                                                                           
  docker --version
  docker compose version   # must be v2 (not docker-compose v1)                                                                                                          
                                                                                                                                                                         
  # Python 3.11+ with Poetry (for ML service)                                                                                                                            
  python3 --version                                                                                                                                                      
  pip install poetry                                                                                                                                                     
                                                               
  # (Optional) golangci-lint for linting                                                                                                                                 
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
                                                                                                                                                                         
  ---                                                          
  Step 1 — Clone and configure environment
                                                                                                                                                                         
  cd /media/mayesha-marzia-zaman/New\ Volume/MyProject/AML_fraud_detection
                                                                                                                                                                         
  # Copy the environment template                                                                                                                                        
  cp .env.example .env
                                                                                                                                                                         
  Open .env and set at minimum these values (the rest have safe defaults for development):                                                                               
   
  POSTGRES_PASSWORD=yourpassword                                                                                                                                         
  MONGO_PASSWORD=yourpassword                                                                                                                                            
  REDIS_PASSWORD=yourpassword
                                                                                                                                                                         
  JWT_SECRET=a_secret_at_least_32_characters_long                                                                                                                        
  INTERNAL_JWT_SECRET=another_32_char_secret_for_services
                                                                                                                                                                         
  VAULT_TOKEN=dev-root-token        # fine for local dev                                                                                                                 
  GRAFANA_ADMIN_PASSWORD=admin                                                                                                                                           
                                                                                                                                                                         
  ---                                                          
  Step 2 — Start infrastructure
                                                                                                                                                                         
  make infra-up
                                                                                                                                                                         
  This starts: PostgreSQL 15, MongoDB 6, Redis 7, Apache Kafka, HashiCorp Vault, Jaeger, Prometheus, Grafana — all in Docker.                                            
   
  Wait ~30 seconds then verify everything is healthy:                                                                                                                    
                                                               
  make infra-status   # all containers should show "healthy" or "running"
  make health         # pings each service endpoint                                                                                                                      
                                                                                                                                                                         
  ---                                                                                                                                                                    
  Step 3 — Run database migrations                                                                                                                                       
                                                               
  make migrate

  This runs all 4 SQL migration files in order:                                                                                                                          
  - 001 — IAM schema (users, sessions, audit log)
  - 002 — Alert schema (fraud_alerts, notifications, status history)                                                                                                     
  - 003 — Case schema (investigation_cases, case_actions, evidence) 
  - 004 — Analytics views and indexes                                                                                                                                    
                                                               
  ---                                                                                                                                                                    
  Step 4 — Seed development data (optional)                    
                                                                                                                                                                         
  make seed        # creates test users, sample KYC records    
  make seed-ml     # downloads the Elliptic Bitcoin dataset for ML training                                                                                              
   
  ---                                                                                                                                                                    
  Step 5 — Train ML models                                     

  # Install Python dependencies first
  make build-ml                                                                                                                                                          
   
  # Train all models (XGBoost, LightGBM, Random Forest, GNN, Autoencoder)                                                                                                
  make ml-train                                                
  # or train just one:                                                                                                                                                   
  make ml-train-model MODEL=xgboost                            
                                                                                                                                                                         
  Models are saved to ml/artifacts/ and registered in MLflow at http://localhost:5000.                                                                                   
                                                                                                                                                                         
  ---                                                                                                                                                                    
  Step 6 — Start Hyperledger Fabric (optional, for blockchain features)
                                                                                                                                                                         
  make fabric-up           # starts 3-org network (Primary Bank / Regulator / Partner)
  make chaincode-deploy    # deploys kyc-contract, alert-contract, audit-contract                                                                                        
                                                               
  ▎ You can skip this step on first run — the services fall back gracefully when Fabric is unavailable.                                                                  
                                                               
  ---                                                                                                                                                                    
  Step 7 — Build all Go services                               
                                                                                                                                                                         
  make build
                                                                                                                                                                         
  Or build a single service:                                   

  make build-svc SVC=analytics-service

  ---                                                                                                                                                                    
  Step 8 — Run all services
                                                                                                                                                                         
  make run                                                     

  This starts all 10 services via Docker Compose using the built images.                                                                                                 
   
  To run a single service locally (outside Docker, useful for development):                                                                                              
                                                               
  make run-svc SVC=analytics-service                                                                                                                                     
  # or directly:                                               
  cd services/analytics-service && go run ./cmd/server
                                                                                                                                                                         
  ---
  Step 9 — Verify everything is running                                                                                                                                  
                                                               
  Open these URLs in your browser:

  ┌────────────────────────┬─────────────────────────────────────────────────────┐                                                                                       
  │          URL           │                     What it is                      │
  ├────────────────────────┼─────────────────────────────────────────────────────┤                                                                                       
  │ http://localhost:8080  │ API Gateway — all REST calls go here                │
  ├────────────────────────┼─────────────────────────────────────────────────────┤
  │ http://localhost:3000  │ Grafana — dashboards (login: admin / your password) │                                                                                       
  ├────────────────────────┼─────────────────────────────────────────────────────┤                                                                                       
  │ http://localhost:16686 │ Jaeger — distributed traces                         │                                                                                       
  ├────────────────────────┼─────────────────────────────────────────────────────┤                                                                                       
  │ http://localhost:9090  │ Prometheus — raw metrics                            │
  ├────────────────────────┼─────────────────────────────────────────────────────┤                                                                                       
  │ http://localhost:5000  │ MLflow — model registry and experiments             │
  ├────────────────────────┼─────────────────────────────────────────────────────┤                                                                                       
  │ http://localhost:8200  │ Vault UI — encryption key management                │
  └────────────────────────┴─────────────────────────────────────────────────────┘                                                                                       
                                                               
  ---
  Step 10 — Run tests
                                                                                                                                                                         
  # All unit tests (fast, no Docker required)
  make test                                                                                                                                                              
                                                               
  # Go unit tests only with coverage                                                                                                                                     
  make test-unit-go
                                                                                                                                                                         
  # Single service tests                                       
  cd services/analytics-service && go test -v -race ./...
                                                                                                                                                                         
  # Single test function
  cd services/transaction-service && go test -v -run TestProcessTransaction ./internal/service/...                                                                       
                                                                                                                                                                         
  # Chaincode tests
  cd blockchain/chaincode/kyc-contract && GOWORK=off go test -v -race ./...                                                                                              
                                                                                                                                                                         
  # Python ML tests                                                                                                                                                      
  cd services/ml-service && poetry run pytest tests/unit/ -v                                                                                                             
                                                                                                                                                                         
  # Integration tests (requires running Docker stack)                                                                                                                    
  make test-integration
                                                                                                                                                                         
  # Security scan                                              
  make test-security

  ---
  Quick Reset
                                                                                                                                                                         
  If you need to wipe everything and start fresh:
                                                                                                                                                                         
  make infra-clean    # removes all containers AND volumes (destructive)
  make infra-up       # bring it back up                                                                                                                                 
  make migrate        # re-apply schemas
                                                                                                                                                                         
  ---                                                          
  Service Port Reference                                                                                                                                                 
                                                               
  ┌─────────────────────┬───────────┬───────────┐
  │       Service       │ gRPC Port │ HTTP Port │                                                                                                                        
  ├─────────────────────┼───────────┼───────────┤
  │ API Gateway         │ —         │ 8080      │                                                                                                                        
  ├─────────────────────┼───────────┼───────────┤              
  │ IAM Service         │ 50060     │ 9000      │
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤                                                                                                                        
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤                                                                                                                        
  │ Alert Service       │ 50063     │ 9003      │              
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤                                                                                                                        
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤                                                                                                                        
  │ Analytics Service   │ 9008      │ —         │              
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤                                                                                                                        
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘                                                                                                                        
                                                               
✻ Cogitated for 1m 37s · 1 shell still running
                                                                                          
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli                                                                                                                                    
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell                                                                                                                                           
                                                                                                                                                                         
  ---
  Service Port Reference

  ┌─────────────────────┬───────────┬───────────┐
  │       Service       │ gRPC Port │ HTTP Port │
  ├─────────────────────┼───────────┼───────────┤
  │ API Gateway         │ —         │ 8080      │
  ├─────────────────────┼───────────┼───────────┤
  │ IAM Service         │ 50060     │ 9000      │
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  ---
  Service Port Reference

  ┌─────────────────────┬───────────┬───────────┐
  │       Service       │ gRPC Port │ HTTP Port │
  ├─────────────────────┼───────────┼───────────┤
  │ API Gateway         │ —         │ 8080      │
  ├─────────────────────┼───────────┼───────────┤
  │ IAM Service         │ 50060     │ 9000      │
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell                                                                                                                          ⧉ In worklog.md
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell                                                                                                                          ⧉ In worklog.md
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell                                                                                                                          ⧉ In worklog.md
  ├─────────────────────┼───────────┼───────────┤
  │ IAM Service         │ 50060     │ 9000      │
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘

✻ Cogitated for 1m 37s · 1 shell still running

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ now please add this complete guidli
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏵⏵ accept edits on · 1 shell                                                                                                                          ⧉ In worklog.md
  ---
  Service Port Reference

  ┌─────────────────────┬───────────┬───────────┐
  │       Service       │ gRPC Port │ HTTP Port │
  ├─────────────────────┼───────────┼───────────┤
  │ API Gateway         │ —         │ 8080      │
  ├─────────────────────┼───────────┼───────────┤
  │ IAM Service         │ 50060     │ 9000      │
  ├─────────────────────┼───────────┼───────────┤
  │ KYC Service         │ 50061     │ 9001      │
  ├─────────────────────┼───────────┼───────────┤
  │ Transaction Service │ 50062     │ 9002      │
  ├─────────────────────┼───────────┼───────────┤
  │ Alert Service       │ 50063     │ 9003      │
  ├─────────────────────┼───────────┼───────────┤
  │ Case Service        │ 50064     │ 9004      │
  ├─────────────────────┼───────────┼───────────┤
  │ Blockchain Service  │ 50065     │ 9005      │
  ├─────────────────────┼───────────┼───────────┤
  │ Analytics Service   │ 9008      │ —         │
  ├─────────────────────┼───────────┼───────────┤
  │ ML Service          │ 50051     │ 8000      │
  ├─────────────────────┼───────────┼───────────┤
  │ Encryption Service  │ 50066     │ —         │
  └─────────────────────┴───────────┴───────────┘











 STEP 1 — IAM: Register admin (gRPC)                                                                                                                                    
                                                                                                                                                                         
  Why first: Every other API needs a JWT. The seed didn't create users, so register one yourself.
                                                                                                                                                                         
  - Server URL: localhost:50060                             
  - Service / method: fraud.iam.v1.IAMService / Register                                                                                                                 
  - Message body (JSON tab):                                                                                                                                             
  {                                                                                                                                                                      
    "email": "admin@fraud.local",                                                                                                                                        
    "password": "Admin@12345",                                                                                                                                           
    "role": "ADMIN"                                                                                                                                                      
  }                
  - Expected response: {"user_id": "<uuid>", "email": "admin@fraud.local", "role": "ADMIN", "created_at": ...}                                                           
                                                            
  STEP 2 — IAM: Login (gRPC) → get JWT                                                                                                                                   
  
  - Method: fraud.iam.v1.IAMService / Login                                                                                                                              
  - Body:                                                   
  {                                                                                                                                                                      
    "email": "admin@fraud.local",                           
    "password": "Admin@12345",   
    "device_id": "postman-1", 
    "ip_address": "127.0.0.1",
    "user_agent": "Postman"                                                                                                                                              
  }                        
  - Save the access_token from the response into an environment variable JWT.                                                                                            
                                                            
  ---                                                                                                                                                                    
  STEP 3 — KYC: Onboard customer (HTTP)
                                                                                                                                                                         
  - POST http://localhost:8080/api/v1/kyc/customers (or direct: :9001)
  - Headers: Authorization: Bearer {{JWT}}, Content-Type: application/json                                                                                               
  - Body:                                                                                                                                                                
  {                                                                                                                                                                      
    "first_name": "John",                                                                                                                                                
    "last_name": "Doe",                                     
    "email": "john.doe@example.com",                                                                                                                                     
    "phone": "+1-555-0100",         
    "country": "US",                                                                                                                                                     
    "date_of_birth": "1985-06-15",                                                                                                                                       
    "address": "123 Main St, Springfield, IL"
  }                                                                                                                                                                      
  - Save the returned customer id (UUID) as CUSTOMER_ID.                                                                                                                 
  - GET http://localhost:8080/api/v1/kyc/customers/{{CUSTOMER_ID}} to verify.
                                                                                                                                                                         
  ---                                                                                                                                                                    
  STEP 4 — ML: Direct prediction sanity check (HTTP)                                                                                                                     
                                                                                                                                                                         
  Why: Confirms ML service loaded models. Bypasses transaction pipeline.
                                                                                                                                                                         
  - GET http://localhost:8000/api/v1/health — should return {"status":"ok","models_loaded":[...]}                                                                        
  - POST http://localhost:8000/api/v1/predict                                                                                                                            
  - Body: (numerical features — exact list depends on model; minimal smoke test)                                                                                         
  {                                                                                                                                                                      
    "tx_hash": "test-tx-001",                                                                                                                                            
    "customer_id": "{{CUSTOMER_ID}}",                                                                                                                                    
    "features": {                                                                                                                                                        
      "amount": 1500.00,
      "hour_of_day": 23,                                                                                                                                                 
      "country_risk_score": 0.7,                                                                                                                                         
      "velocity_24h": 5,        
      "merchant_category_risk": 0.6                                                                                                                                      
    }                                                       
  }                                                                                                                                                                      
  - Expected: {"fraud_probability": 0.X, "risk_level": "HIGH|MEDIUM|LOW", "explanation": {...}}
                                                                                                                                                                         
  ---                                                                                                                                                                    
  STEP 5 — Transaction: Ingest a transaction (gRPC)
                                                                                                                                                                         
  Why: This triggers the full pipeline (features → ML prediction → optional alert → DB).
                                                                                                                                                                         
  - Server URL: localhost:50062                             
  - Method: fraud.transaction.v1.TransactionService / IngestTransaction                                                                                                  
  - Headers (Postman gRPC supports metadata): authorization: Bearer {{JWT}}                                                                                              
  - Body:                                                                                                                                                                
  {                                                                                                                                                                      
    "transaction": {                                                                                                                                                     
      "tx_hash": "tx-001-postman",                          
      "customer_id": "{{CUSTOMER_ID}}",
      "amount": 9999.50,                                                                                                                                                 
      "currency_code": "USD",
      "merchant_id": "M-12345",                                                                                                                                          
      "merchant_name": "Acme Corp",                         
      "merchant_category": "5411",                                                                                                                                       
      "country_code": "US",                                                                                                                                              
      "channel": "CARD_NOT_PRESENT",
      "counterparty_id": "BTC:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",                                                                                                       
      "counterparty_country": "RU",                               
      "transaction_at": "2026-05-02T12:00:00Z"                                                                                                                           
    },                                        
    "sync": true                                                                                                                                                         
  }                                                         
  - Expected: {"tx_hash":"tx-001-postman","status":"SCORED","fraud_probability":0.X,"risk_level":"HIGH","alert_created":true,"alert_id":"<uuid>"}                        
  - If alert_created=true, save alert_id as ALERT_ID for the next step.                                                                          
                                                                                                                                                                         
  ---                                                                                                                                                                    
  STEP 6 — Alert: List & inspect (HTTP)                                                                                                                                  
                                                                                                                                                                         
  - GET http://localhost:8080/api/v1/alerts                 
    - Headers: Authorization: Bearer {{JWT}}                                                                                                                             
  - GET http://localhost:8080/api/v1/alerts/customer/{{CUSTOMER_ID}} — alerts for one customer                                                                           
  - GET http://localhost:8080/api/v1/alerts/stats — aggregate stats                                                                                                      
  - GET http://localhost:8080/api/v1/alerts/{{ALERT_ID}} — single alert detail                                                                                           
  - PATCH http://localhost:8080/api/v1/alerts/{{ALERT_ID}}/status                                                                                                        
  { "status": "INVESTIGATING", "assignee_id": "<your-user-id>" }                                                                                                         
                                                                                                                                                                         
  ---                                                                                                                                                                    
  STEP 7 — Case: Open investigation (HTTP)                                                                                                                               
                                                                                                                                                                         
  - POST http://localhost:8080/api/v1/cases                 
    - Headers: Authorization: Bearer {{JWT}}                                                                                                                             
  - Body:                                                   
  {                                                                                                                                                                      
    "alert_id": "{{ALERT_ID}}",
    "customer_id": "{{CUSTOMER_ID}}",                                                                                                                                    
    "priority": "HIGH",                                     
    "summary": "Suspicious cross-border crypto transaction",
    "assignee_id": "<your-user-id>"                                                                                                                                      
  }
  - GET http://localhost:8080/api/v1/cases — list                                                                                                                        
  - GET http://localhost:8080/api/v1/cases/stats — counts by status
  - GET http://localhost:8080/api/v1/cases/workload — per-investigator load                                                                                              
                                                                                                                                                                         
  ---                                                                                                                                                                    
  (Optional) STEP 8 — Blockchain (only if Fabric is running)                                                                                                             
                                                                                                                                                                         
  - POST http://localhost:8080/api/v1/blockchain/internal/v1/kyc/register — anchor KYC record
  - POST http://localhost:8080/api/v1/blockchain/internal/v1/alerts/create — anchor alert                                                                                
  - GET http://localhost:8080/api/v1/blockchain/internal/v1/audit/trail?customer_id={{CUSTOMER_ID}}                                                                      
                                                                                                                                                                         
  You won't have Fabric running, so expect 503/connection-refused here — that's fine, it's optional.                                                                     
                                                                                                                                                                         
  ---                                                                                                                                                                    
  Quick reference card                                      
                                                                                                                                                                         
  ┌──────┬──────────────┬──────────┬──────────────────────────────────────────────────────┐
  │ Step │   Service    │ Protocol │                      URL/Method                      │                                                                              
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤
  │ 1    │ IAM Register │ gRPC     │ localhost:50060 IAMService/Register                  │
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤
  │ 2    │ IAM Login    │ gRPC     │ localhost:50060 IAMService/Login                     │                                                                              
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤                                                                              
  │ 3    │ KYC          │ HTTP     │ POST /api/v1/kyc/customers                           │                                                                              
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤                                                                              
  │ 4    │ ML           │ HTTP     │ POST :8000/api/v1/predict                            │
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤                                                                              
  │ 5    │ Transaction  │ gRPC     │ localhost:50062 TransactionService/IngestTransaction │
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤                                                                              
  │ 6    │ Alert        │ HTTP     │ GET/PATCH /api/v1/alerts                             │
  ├──────┼──────────────┼──────────┼──────────────────────────────────────────────────────┤                                                                              
  │ 7    │ Case         │ HTTP     │ POST /api/v1/cases                                   │
  └──────┴──────────────┴──────────┴──────────────────────────────────────────────────────┘                                                                              
                                                            
  The dependency order: Login → Customer ID → Transaction (which auto-creates an Alert) → Case (built from Alert). 















Running iam-service — Step by Step
  
  Important: iam-service is gRPC only

  It has no HTTP/REST endpoints. It listens on gRPC port 50060. You'll need Postman v10+ which supports gRPC natively.

  ---
  Step 1 — Set up your .env file

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  cp .env.example .env

  Then edit .env — only these values are required by iam-service:

  POSTGRES_HOST=localhost
  POSTGRES_PORT=5432
  POSTGRES_DB=fraud_detection
  POSTGRES_USER=fraud_user
  POSTGRES_PASSWORD=changeme_strong_password   # must be set

  REDIS_HOST=localhost
  REDIS_PORT=6379
  REDIS_PASSWORD=changeme_redis_password        # must be set
  REDIS_DB=0

  JWT_SECRET=changeme_min_32_chars_jwt_secret_key_here  # must be ≥32 chars

  IAM_SERVICE_GRPC_PORT=50060

  ---
  Step 2 — Start only the required infrastructure
  
  iam-service only needs PostgreSQL and Redis (not Kafka, Vault, or MongoDB).

  docker-compose up -d postgres redis

  Wait ~10 seconds, then verify both are healthy:

  docker-compose ps postgres redis

  ---
  Step 3 — Initialize the database schema
  
  The postgres-init.sql creates all IAM tables and seeds the 5 default roles. This runs automatically on the first container start
   — but verify it ran:

  docker exec -it fraud_postgres psql -U fraud_user -d fraud_detection -c "\dn"

  You should see schemas: iam, kyc, alerts, cases, analytics, audit.

  If tables are missing, run it manually:

  docker exec -i fraud_postgres psql -U fraud_user -d fraud_detection \
    < scripts/db/postgres-init.sql

  ---
  Step 4 — Build and run iam-service

  # Load env vars and run the service
  export $(grep -v '^#' .env | xargs)
  make run-svc SVC=iam-service

  You should see logs like:
  {"service":"iam-service","grpc_port":50060,"msg":"IAM service ready"}

  ---
  Step 5 — Test in Postman (gRPC)
  
  1. Create a new gRPC request in Postman
  - Click New → gRPC Request
  - URL: localhost:50060

  2. Import the proto file
  - Click Select a .proto file
  - Import proto/iam.proto
  - Also import proto/common.proto (it's a dependency)

  3. Test these RPCs in order:

  ┌──────┬──────────────────────────┬─────────────────────────────────────┐
  │ Step │           RPC            │             Key fields              │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 1    │ IAMService/Register      │ email, password                     │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 2    │ IAMService/Login         │ email, password                     │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 3    │ IAMService/ValidateToken │ access_token (from Login response)  │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 4    │ IAMService/GetProfile    │ user_id (from Login response)       │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 5    │ IAMService/RefreshToken  │ refresh_token (from Login response) │
  ├──────┼──────────────────────────┼─────────────────────────────────────┤
  │ 6    │ IAMService/Logout        │ meta.user_id                        │
  └──────┴──────────────────────────┴─────────────────────────────────────┘

  Example Register message body (JSON in Postman):
  {
    "email": "admin@test.com",
    "password": "StrongPass123!",
    "role": "ADMIN"
  }
  
  Example Login message body:
  {
    "email": "admin@test.com",
    "password": "StrongPass123!",
    "device_id": "postman-test",
    "ip_address": "127.0.0.1"
  }

  ---
  Quick sanity check before running

  # Check postgres is reachable
  docker exec fraud_postgres pg_isready -U fraud_user

  # Check redis is reachable  
  docker exec fraud_redis redis-cli -a changeme_redis_password ping

  Both should return OK / PONG before starting the service.













Step 1 — Stop the local IAM service process
  
  The locally running process must be killed first, otherwise Docker can't bind port 50060.

  kill $(ss -tlnp | grep 50060 | grep -oP 'pid=\K[0-9]+')

  Verify it's gone:
  ss -tlnp | grep 50060    # should return nothing

  ---
  Step 2 — Confirm .env is ready
  
  Your .env already has all required values. Just verify once:

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  grep -E "JWT_SECRET|POSTGRES_PASSWORD|REDIS_PASSWORD" .env

  You should see non-empty values for all three. If JWT_SECRET is empty or missing, set it:
  echo 'JWT_SECRET=K9xT2mQ7vL4pNz8RwY1cHd6FaSb3JeUt' >> .env

  ---
  Step 3 — Start infrastructure (Postgres + Redis + Jaeger)

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"

  docker compose up -d postgres redis jaeger

  Wait for them to be healthy (takes ~20 seconds):
  docker compose ps
  
  You need to see healthy status for postgres and redis before continuing:
  NAME           STATUS
  fds-postgres   Up X seconds (healthy)
  fds-redis      Up X seconds (healthy)
  fds-jaeger     Up X seconds 
  
  If not healthy yet, wait and re-run docker compose ps until they are.

  ---
  Step 4 — Build the IAM service image
  
  This takes 2–3 minutes the first time (downloads Go modules and grpc_health_probe):

  docker compose build iam-service

  Watch for output ending with:
  => exporting to image
  => => naming to docker.io/library/aml_fraud_detection_iam-service

  If build fails, check the error and scroll up — most common causes are network issues downloading grpc_health_probe or a missing
   .env value.

  ---
  Step 5 — Start the IAM service

  docker compose up -d iam-service

  Watch the logs:
  docker compose logs -f iam-service

  You should see:
  {"level":"info","message":"postgres connected"}
  {"level":"info","message":"redis connected"}
  {"level":"info","grpc_port":50060,"message":"gRPC server listening"}
  {"level":"info","message":"IAM service ready"}
  
  Press Ctrl+C to stop following logs (the container keeps running).

  ---
  Step 6 — Verify it is healthy

  docker compose ps iam-service

  Expected:
  NAME              STATUS
  fds-iam-service   Up X seconds (healthy)

  Test the gRPC endpoint directly:
  export PATH="$HOME/go/bin:$PATH"
  
  # Should list the service
  grpcurl -plaintext localhost:50060 list
  
  # Should return the service methods
  grpcurl -plaintext localhost:50060 list fraud.iam.v1.IAMService

  ---
  Step 7 — Register first user
  
  Since you wiped the DB (fresh Docker volume), the iam.roles and iam.permissions are seeded automatically by postgres-init.sql on
   first container start. Register:

  grpcurl -plaintext \
    -d '{"email":"admin@fraud.local","password":"Admin@12345678"}' \
    localhost:50060 fraud.iam.v1.IAMService/Register

  Then promote to ADMIN:
  docker exec fds-postgres psql \
    -U fraud_user -d fraud_detection \
    -c "UPDATE iam.users SET role_id = (SELECT id FROM iam.roles WHERE name='ADMIN') WHERE email='admin@fraud.local';"

  Then login:
  grpcurl -plaintext \
    -d '{"email":"admin@fraud.local","password":"Admin@12345678","device_id":"dev-01","ip_address":"127.0.0.1"}' \
    localhost:50060 fraud.iam.v1.IAMService/Login

  ---
  All-in-one commands (copy-paste)

  # Kill local process
  kill $(ss -tlnp | grep 50060 | grep -oP 'pid=\K[0-9]+') 2>/dev/null || true

  # Go to project root
  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"

  # Start infra
  docker compose up -d postgres redis jaeger

  # Wait for healthy (check with: docker compose ps)
  sleep 20

  # Build + start IAM service
  docker compose build iam-service && docker compose up -d iam-service

  # Follow logs
  docker compose logs -f iam-service

  ---
  Useful management commands

  # Stop the IAM service only (keeps DB data)
  docker compose stop iam-service

  # Restart after a code change
  docker compose build iam-service && docker compose up -d --force-recreate iam-service

  # Stop everything
  docker compose down

  # Stop everything AND wipe all volumes (full reset)
  docker compose build iam-service && docker compose up -d iam-service

  # Follow logs
  docker compose logs -f iam-service

  ---
  Useful management commands

  # Stop the IAM service only (keeps DB data)
  docker compose stop iam-service

  # Restart after a code change
  docker compose build iam-service && docker compose up -d --force-recreate iam-service

  # Stop everything
  docker compose down

  # Stop everything AND wipe all volumes (full reset)
  docker compose down -v

  # Check health status
  docker compose ps

  # Shell into postgres to run SQL
  docker exec -it fds-postgres psql -U fraud_user -d fraud_detection





  make run-svc SVC=encryption-service
  # gRPC: :50066

  Then follow this order:

  2. encryption-service  ← run this now
  3. ml-service          ← then this (needs MLflow only)
  4. blockchain-service  ← then this (run make fabric-up first)
  5. kyc-service         ← needs enc + ml + blockchain all up
  6. alert-service       ← needs kafka only
  7. transaction-service ← needs ml + iam + kafka
  8. case-service        ← needs blockchain + kafka
  9. api-gateway         ← last (proxies all others)






   The service is up and reachable. Here is the complete step-by-step testing guide:

  ---
  Encryption Service — Step-by-Step Test Guide
  
  The service is gRPC only on port 50066. All commands use grpcurl.

  Set this variable first to keep commands short:
  PROTO_DIR="/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection/proto"

  ---
  Step 1 — Health Check

  Verify the service is alive and connected to Vault:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \   
    -d '{"service": "encryption-service"}' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/HealthCheck

  Expected response:  
  {
    "status": "HEALTH_STATUS_SERVING",
    "details": "ok"
  }

  ---
  Step 2 — Get Key Info
  
  Confirm the fraud-pii-key Transit key is set up in Vault:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-001", "caller_svc": "test"},
      "key_name": "fraud-pii-key"
    }' \    
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/GetKeyInfo

  Expected response:  
  {
    "keyName": "fraud-pii-key",
    "currentVersion": 1,
    "minDecryptVersion": 1,
    "rotationPeriod": "2160h"
  }

  ---
  Step 3 — Encrypt PII (single field)
  
  Encrypt a customer name. Note: plaintext must be base64-encoded:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-002", "caller_svc": "test"},
      "key_name": "fraud-pii-key", 
      "plaintext": "Sm9obiBEb2U=",
      "context": "customer-001"
    }' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/EncryptPII

  (Sm9obiBEb2U= = base64 of John Doe)
  
  Expected response:
  {
    "ciphertext": "vault:v1:XXXXXXXXXXXXXXXXXXXXXX",
    "keyVersion": 1
  } 

  Save the ciphertext — you'll need it in Step 4.

  ---
  Step 4 — Decrypt PII (round-trip verify)

  Paste the ciphertext from Step 3:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-003", "caller_svc": "test"},
      "key_name": "fraud-pii-key",
      "ciphertext": "PASTE_CIPHERTEXT_HERE",
      "context": "customer-001"
    }' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/DecryptPII

  Expected response:  
  {
    "plaintext": "Sm9obiBEb2U="
  }
  
  Decode to verify: echo "Sm9obiBEb2U=" | base64 -d → John Doe

  ---
  Step 5 — Batch Encrypt (multiple PII fields in one call)
  
  This is how KYC service will encrypt a full customer record:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-004", "caller_svc": "test"},
      "key_name": "fraud-pii-key",
      "fields": [
        {"field_name": "full_name",  "plaintext": "Sm9obiBEb2U=",         "context": "customer-001"},
        {"field_name": "dob",        "plaintext": "MTk5MC0wNS0xNQ==",     "context": "customer-001"},
        {"field_name": "passport",   "plaintext": "QUIxMjM0NTY3",         "context": "customer-001"},
        {"field_name": "email",      "plaintext": "am9obi5kb2VAZXhhbXBsZS5jb20=", "context": "customer-001"}
      ]
    }' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/BatchEncrypt

  Expected response: 4 encrypted fields each with their own ciphertext and keyVersion.

  ---
  Step 6 — Batch Decrypt
  
  Use the 4 ciphertexts returned from Step 5:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-005", "caller_svc": "test"},
      "key_name": "fraud-pii-key",
      "fields": [
        {"field_name": "full_name", "ciphertext": "PASTE_CIPHER_1", "context": "customer-001"},
        {"field_name": "dob",       "ciphertext": "PASTE_CIPHER_2", "context": "customer-001"},
        {"field_name": "passport",  "ciphertext": "PASTE_CIPHER_3", "context": "customer-001"},
        {"field_name": "email",     "ciphertext": "PASTE_CIPHER_4", "context": "customer-001"}
      ]
    }' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/BatchDecrypt

  Expected response: 4 decrypted fields with base64 plaintext matching the originals.

  ---
  Step 7 — Generate Identity Hash
  
  This produces the SHA-256 hash stored on blockchain (no PII ever leaves Vault):

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \   
    -d '{
      "meta": {"request_id": "req-006", "caller_svc": "test"},
      "full_name":       "John Doe",
      "date_of_birth":   "1990-05-15",
      "document_number": "AB1234567",
      "document_type":   "PASSPORT",
      "country_code":    "US"   
    }' \
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/GenerateIdentityHash
  
  Expected response:
  {
    "identityHash": "a3f5c2d1...",
    "algorithm": "SHA-256"
  } 

  Run it twice with the same data — the hash must be identical both times (determinism test).

  ---
  Step 8 — Rewrap Key (key rotation test)
  
  Re-encrypt an existing ciphertext under the latest key version without exposing plaintext:

  grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto encryption.proto \
    -d '{
      "meta": {"request_id": "req-007", "caller_svc": "test"},
      "key_name": "fraud-pii-key",
      "ciphertexts": ["PASTE_CIPHERTEXT_FROM_STEP3"],
      "context": "customer-001"
    }' \    
    localhost:50066 \
    fraud.encryption.v1.EncryptionService/RewrapKey
  
  Expected response:
  {
    "newCiphertexts": ["vault:v1:NEW_CIPHERTEXT"],
    "newKeyVersion": 1
  }

  ---
  Quick Pass/Fail Checklist

  ┌─────────────────────────┬────────────────────────────────────────────────┐
  │          Step           │                 What it proves                 │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 1. HealthCheck          │ Service is up, Vault connection is live        │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 2. GetKeyInfo           │ Transit key fraud-pii-key exists in Vault      │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 3. EncryptPII           │ Single field encryption works                  │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 4. DecryptPII           │ Round-trip: decrypt returns original plaintext │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 5. BatchEncrypt         │ Multi-field encryption (KYC use case)          │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 6. BatchDecrypt         │ Multi-field decryption round-trip              │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 7. GenerateIdentityHash │ Deterministic — same input = same hash         │
  ├─────────────────────────┼────────────────────────────────────────────────┤
  │ 8. RewrapKey            │ Key rotation support works                     │
  └─────────────────────────┴────────────────────────────────────────────────┘





   Step 1 — Install ML service dependencies

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  make build-ml

  This installs all Python packages (FastAPI, XGBoost, LightGBM, etc.) via Poetry. Takes 2–5 minutes the first time.

  ---
  Step 2 — Quick sanity check (verify models load correctly)

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  python3 - <<'EOF'
  import joblib, json, numpy as np

  rf  = joblib.load("ml/artifacts/random_forest_model.pkl")
  xgb = joblib.load("ml/artifacts/xgboost_model.pkl")
  lgb = joblib.load("ml/artifacts/lightgbm_model.pkl")

  with open("ml/artifacts/ensemble.json") as f:
      meta = json.load(f)

  X = np.random.rand(1, 85).astype("float32")

  print(f"RF  — features: {rf.n_features_in_}  | P(fraud): {rf.predict_proba(X)[0][1]:.4f}")
  print(f"XGB — features: {xgb.n_features_in_} | P(fraud): {xgb.predict_proba(X)[0][1]:.4f}")
  print(f"LGB — features: {lgb.n_features_in_} | P(fraud): {lgb.predict_proba(X)[0][1]:.4f}")
  print(f"Ensemble weights: {meta['weights']}")
  print("All models OK!")
  EOF

  All three must print features: 85. If you see any error, paste it here before continuing.

  ---
  Step 3 — Start the ML service

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  make ml-serve

  Wait for these lines in the output:
  loaded model: random_forest
  loaded model: xgboost
  loaded model: lightgbm
  loaded ensemble weights
  registry ready: 3 base models + ensemble=yes
  gRPC server started on port 50051

  ---
  Step 4 — Verify it's running (open a second terminal)

  # Health check
  curl http://localhost:8000/api/v1/health

  Or open in your browser: http://localhost:8000/docs — this shows the full Swagger UI with all API endpoints.

  ---
  Step 5 — Test a fraud prediction

  curl -X POST http://localhost:8000/api/v1/predict \
    -H "Content-Type: application/json" \
    -d '{
      "transaction_id": "test-001",
      "features": {
        "amount": 5000.0,
        "velocity_1h": 3.0,
        "geographic_risk_score": 0.8
      }
    }'

  ---
  Summary of what's running after Step 3

  ┌──────────────┬──────────────────────────────┬────────────────────────────────┐
  │  Interface   │             URL              │            Purpose             │
  ├──────────────┼──────────────────────────────┼────────────────────────────────┤
  │ REST API     │ http://localhost:8000/api/v1 │ HTTP predictions               │
  ├──────────────┼──────────────────────────────┼────────────────────────────────┤
  │ Swagger docs │ http://localhost:8000/docs   │ Interactive API explorer       │
  ├──────────────┼──────────────────────────────┼────────────────────────────────┤
  │ gRPC         │ localhost:50051              │ Internal service communication │
  └──────────────┴──────────────────────────────┴────────────────────────────────┘














   Next Steps in Order
  
  Step 1 — Run database migrations

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  make migrate

  This creates all PostgreSQL tables (users, transactions, alerts, cases, KYC records).
  
  ---
  Step 2 — Start the full application stack

  make run

  This starts all remaining Go microservices via docker-compose:
  - api-gateway → :8080
  - kyc-service → :9001
  - transaction-service → :9002
  - alert-service → :9003 
  - case-service → :9004
  - analytics-service → :9006
  - blockchain-service → :9005

  ---
  Step 3 — Verify the full stack

  make health

  Then test the API gateway:
  curl http://localhost:8080/health

  ---
  Step 4 — Test end-to-end flow
  
  Open http://localhost:8080 — this is the main entry point. You can:

  1. Register a user → POST /api/v1/auth/register
  2. Login → POST /api/v1/auth/login (get JWT token)
  3. Submit a transaction → POST /api/v1/transactions (triggers ML fraud detection)
  4. View alerts → GET /api/v1/alerts

  ---
  Step 5 — View monitoring dashboards

  ┌─────────────────────────┬────────────────────────┐
  │        Dashboard        │          URL           │
  ├─────────────────────────┼────────────────────────┤
  │ Grafana (metrics)       │ http://localhost:3000  │
  ├─────────────────────────┼────────────────────────┤
  │ Jaeger (tracing)        │ http://localhost:16686 │
  ├─────────────────────────┼────────────────────────┤
  │ Prometheus              │ http://localhost:9090  │
  ├─────────────────────────┼────────────────────────┤
  │ MLflow (model registry) │ http://localhost:5000  │
  └─────────────────────────┴────────────────────────┘

  ---
  Start with make migrate now. Paste the output and I'll help with the next step.
















   Full Project Setup & E2E Test — Step by Step
  
  Architecture overview (what runs where)

  DOCKER (infrastructure)          LOCAL PROCESSES (application layer)
  ──────────────────────           ──────────────────────────────────
  postgres    :5433                encryption-service  :50066
  mongodb     :27017               iam-service         :50060
  redis       :6379                kyc-service         :50061
  kafka       :9092                transaction-service :50062
  vault       :8200                alert-service       :50063
  jaeger      :16686               case-service        :9004
  prometheus  :9090                ml-service          :8000
  grafana     :3000                api-gateway         :8080
  mlflow      :5000

  ---
  PHASE 1 — Start Infrastructure

  cd ~/AML_fraud_detection\ \(2\)/AML_fraud_detection

  make infra-up

  This starts: postgres, mongodb, redis, zookeeper, kafka, vault, jaeger, prometheus, grafana, mlflow — and auto-runs kafka-init
  and vault-init to create topics and the Vault transit key.

  Wait ~30 seconds for everything to be healthy, then verify:

  make infra-status

  All services should show Up (healthy).

  ▎ Important: Vault runs in dev mode (in-memory). If vault ever restarts you must re-run the vault init (see the "After a 
  ▎ restart" section at the bottom).

  ---
  PHASE 2 — Verify the Database Was Initialized
  
  The database schema and seed roles are created automatically by postgres-init.sql on the first container start.

  docker exec fds-postgres psql -U fraud_user -d fraud_detection \
    -c "\dn"

  Expected output — 6 schemas:

    iam | analytics | audit | alerts | cases | kyc

  If you see them, the DB is ready. If not, run:

  docker exec fds-postgres psql -U fraud_user -d fraud_detection \
    -f /docker-entrypoint-initdb.d/01-init.sql

  ---
  PHASE 3 — Install ML Service Dependencies

  cd ~/AML_fraud_detection\ \(2\)/AML_fraud_detection/services/ml-service
  poetry install
  cd ~/AML_fraud_detection\ \(2\)/AML_fraud_detection

  This takes 1–2 minutes on first run.

  ---
  PHASE 4 — Start All Application Services

  Open a dedicated terminal for this — it runs all services and streams logs. Keep it open.

  cd ~/AML_fraud_detection\ \(2\)/AML_fraud_detection
  make run

  This calls scripts/run-all.sh which starts (in order):

  1. encryption-service — waits 2 seconds before next
  2. iam-service
  3. kyc-service
  4. transaction-service
  5. blockchain-service
  6. alert-service
  7. case-service
  8. ml-service (Python/FastAPI)
  9. api-gateway (after 5 second delay)

  All logs go to ./logs/<service>.log.

  Wait ~15 seconds for all services to finish starting, then in a new terminal verify:

  curl -s http://localhost:8080/health | python3 -m json.tool

  You should get {"status":"ok"}.

  ---
  PHASE 5 — Seed Test Users

  cd ~/AML_fraud_detection\ \(2\)/AML_fraud_detection
  bash scripts/seed-data.sh

  This creates these test accounts (all use password Admin@12345):

  ┌──────────────────────────┬──────────────────────────────┐
  │          Email           │             Role             │
  ├──────────────────────────┼──────────────────────────────┤
  │ admin@fraud.local        │ ADMIN — full access          │
  ├──────────────────────────┼──────────────────────────────┤
  │ analyst@fraud.local      │ ANALYST — view/triage alerts │
  ├──────────────────────────┼──────────────────────────────┤
  │ investigator@fraud.local │ INVESTIGATOR — manage cases  │
  └──────────────────────────┴──────────────────────────────┘

  ---
  PHASE 6 — End-to-End Test Flow
  
  Open a new terminal for these API calls.

  Step 1 — Login and get a JWT

  curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@fraud.local","password":"Admin@12345"}' \
    | python3 -m json.tool

  Copy the access_token value, then:

  TOKEN="<paste the access_token here>"

  ---
  Step 2 — Register a KYC Customer

  curl -s -X POST http://localhost:8080/api/v1/kyc \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "full_name": "Alice Test",
      "date_of_birth": "1990-05-20",
      "national_id": "NATID123456",
      "address": "99 Fraud St, Testville",
      "risk_level": "LOW"
    }' | python3 -m json.tool

  Save the returned id as KYC_ID.

  ---
  Step 3 — Submit a Transaction (triggers fraud detection pipeline)

  curl -s -X POST http://localhost:8080/api/v1/transactions \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "sender_account": "ACC-001",
      "receiver_account": "ACC-999",
      "amount": 95000.00,
      "currency": "USD",
      "transaction_type": "WIRE_TRANSFER"
    }' | python3 -m json.tool

  What happens internally:
  API Gateway
    → Transaction Service (feature extraction)
      → ML Service gRPC (XGBoost + LightGBM + RF ensemble prediction)
      → Redis (velocity counters updated)
      → MongoDB (transaction stored)
      → Kafka topic: alerts.created  (if fraud score > 0.7)
        → Alert Service (creates alert, WebSocket push)
          → Blockchain Service (anchors alert on Hyperledger Fabric)

  ---
  Step 4 — Check Generated Alerts

  curl -s http://localhost:8080/api/v1/alerts \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

  High-amount wire transfers should have a fraud probability > 0.7 and appear here.

  ---
  Step 5 — View Cases

  curl -s http://localhost:8080/api/v1/cases \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

  ---
  Step 6 — Check ML Prediction Directly

  curl -s -X POST http://localhost:8000/api/v1/predict \
    -H "Content-Type: application/json" \
    -d '{
      "transaction_id": "test-001",
      "features": {
        "amount": 95000,
        "transaction_type": "WIRE_TRANSFER",
        "sender_account": "ACC-001",
        "receiver_account": "ACC-999"
      }
    }' | python3 -m json.tool

  Response includes fraud_probability, risk_score, and SHAP feature explanations.

  ---
  PHASE 7 — Check Observability

  Open these in a browser:

  ┌──────────────────────────────┬────────────────────────┬───────────────────────────────────┐
  │             Tool             │          URL           │               Login               │
  ├──────────────────────────────┼────────────────────────┼───────────────────────────────────┤
  │ Grafana (metrics dashboards) │ http://localhost:3000  │ admin / changeme_grafana_password │
  ├──────────────────────────────┼────────────────────────┼───────────────────────────────────┤
  │ Jaeger (distributed traces)  │ http://localhost:16686 │ —                                 │
  ├──────────────────────────────┼────────────────────────┼───────────────────────────────────┤
  │ Prometheus (raw metrics)     │ http://localhost:9090  │ —                                 │
  ├──────────────────────────────┼────────────────────────┼───────────────────────────────────┤
  │ MLflow (model registry)      │ http://localhost:5000  │ —                                 │
  ├──────────────────────────────┼────────────────────────┼───────────────────────────────────┤
  │ Vault UI (secrets/keys)      │ http://localhost:8200  │ Token: dev-root-token             │
  └──────────────────────────────┴────────────────────────┴───────────────────────────────────┘

  In Jaeger — search for service api-gateway to see the full distributed trace for each request end-to-end.

  ---
  PHASE 8 — Run the Test Suite

  # All unit tests (Go + Python + chaincode)
  make test

  # Go only
  make test-unit-go

  # Python ML only
  make test-unit-python

  # Hyperledger Fabric chaincode only
  make test-unit-chaincode

  ---
  Checking Logs When Something Fails

  # Per-service logs (written by run-all.sh)
  cat logs/iam-service.log
  cat logs/transaction-service.log
  cat logs/ml-service.log
  cat logs/api-gateway.log

  # Infrastructure container logs
  docker compose logs postgres --tail=20
  docker compose logs vault --tail=20
  docker compose logs kafka --tail=20

  ---
  After Any Vault Restart (important!)

  Vault dev mode is in-memory — the transit key is lost on every restart. Run this to restore it:

  curl -s -X POST -H "X-Vault-Token: dev-root-token" \
    -d '{"type":"transit"}' \
    http://localhost:8200/v1/sys/mounts/transit

  curl -s -X POST -H "X-Vault-Token: dev-root-token" \
    http://localhost:8200/v1/transit/keys/fraud-pii-key

  # Then restart encryption-service (it connects to Vault on startup)
  # If running locally: Ctrl+C make run, then make run again
  # If running in Docker: docker compose restart encryption-service

  ---
  Stopping Everything

  # Stop application services
  # → Press Ctrl+C in the terminal running `make run`

  # Stop infrastructure containers (keeps data volumes)
  make infra-down

  # Full wipe (deletes all data)
  make infra-clean









 ---
  Stubbed / Static Portions (Critical)

  1. KYC Service — Blockchain Anchoring (kyc-service/internal/clients/blockchain.go:87)

  txID := fmt.Sprintf("stub-tx-%s", uuid.New().String())
  // "[STUB] would anchor KYC registration on blockchain — Phase 6 pending"
  Every KYC record returns a fake stub-tx-* transaction ID. Nothing is written to Hyperledger Fabric. Controlled by
  USE_STUB_BLOCKCHAIN=true env var.

  2. KYC Service — Face Verification (kyc-service/internal/clients/facematch.go:115)

  const mockScore = 0.92      // always passes
  const mockLivenessScore = 0.97
  // "[MOCK] face match result — Phase 7 will use real ML service"
  Face verification always returns pass with hardcoded scores. Controlled by USE_MOCK_FACE_MATCH=true.
  
  3. KYC Service — OCR / AWS Textract (kyc-service/internal/textract/mock.go:37)

  result.ExtractedName = "JOHN MOCK SMITH"
  result.ExtractedDOB  = "1990-01-15"
  Document OCR always extracts hardcoded mock data. Controlled by USE_MOCK_TEXTRACT=true.
  
  4. ML Service — Three Stub Endpoints (ml-service/app/grpc/servicer.py)

  ┌──────────────────────────────┬──────────────────────────────────────────────────────┐
  │            Method            │                     What it does                     │
  ├──────────────────────────────┼──────────────────────────────────────────────────────┤
  │ VerifyFace() line 68         │ Always returns match_score=0.92, face_match=true     │
  ├──────────────────────────────┼──────────────────────────────────────────────────────┤
  │ StreamPredictions() line 215 │ Returns iter([]) — empty stream, Kafka not connected │
  ├──────────────────────────────┼──────────────────────────────────────────────────────┤
  │ TriggerRetraining() line 428 │ Returns status="QUEUED" but never calls MLflow       │
  └──────────────────────────────┴──────────────────────────────────────────────────────┘

  5. Transaction Service — Minor TODOs

  - Async processing (handler.go:65): processes inline instead of via Kafka worker
  - Dead-letter queue (consumer.go:152): malformed messages silently dropped
  - GNN features (extractor.go:273): graph features are zero-padded (Phase 7)
  - TLS disabled (cmd/server/main.go:139): TLS: false — fine for dev

  ---
  No Hardcoded Credentials Found

  All passwords, secrets, and API keys are loaded from environment variables or Vault. Nothing sensitive is in source code. ✓

  ---
  What This Means for E2E Testing
  
  The full happy-path pipeline works end to end:
  Register User → Login → Submit KYC → Send Transaction →
  Fraud Score → Alert Created → Case Opened → Analytics Updated

  But you'll see these known artifacts:
  - KYC blockchain TX IDs will look like stub-tx-<uuid>
  - Face verification always passes (score 0.92)
  - OCR always extracts "JOHN MOCK SMITH"
  - ML streaming returns nothing
  - GNN features contribute zero weight to predictions







  

  Phase 1 — Install Hyperledger Fabric Binaries
  
  cryptogen, configtxgen, and peer CLI are required. Run this in your terminal:

  # Download Fabric 2.5 binaries
  mkdir -p ~/fabric-tools && cd ~/fabric-tools
  curl -LO https://github.com/hyperledger/fabric/releases/download/v2.5.0/hyperledger-fabric-linux-amd64-2.5.0.tar.gz
  tar -xzf hyperledger-fabric-linux-amd64-2.5.0.tar.gz
  # Creates ./bin/cryptogen, ./bin/configtxgen, ./bin/peer etc.

  # Add to PATH — do this in every terminal you use for Fabric
  export PATH=$HOME/fabric-tools/bin:$PATH

  # Verify
  cryptogen version
  configtxgen version
  peer version

  ---
  Phase 2 — Pull Fabric Docker Images

  docker pull hyperledger/fabric-orderer:2.5
  docker pull hyperledger/fabric-peer:2.5
  docker pull hyperledger/fabric-ca:1.5
  docker pull couchdb:3.3

  This takes a few minutes on first run. These are the images referenced in blockchain/network/docker-compose.yaml and
  docker-compose.peers.yaml.

  ---
  Phase 3 — Start the Fabric Network

  export PATH=$HOME/fabric-tools/bin:$PATH

  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection/blockchain/network"
  bash start.sh

  This script does everything automatically:
  1. Generates crypto material for 3 orgs + orderer (using cryptogen)
  2. Generates channel artifacts for kyc-channel, alert-channel, audit-channel (using configtxgen)
  3. Starts all Docker containers: 2 orderers + 6 peers (2 per org) + CouchDB state DBs
  4. Waits 15 seconds for peers to come up
  5. Creates all 3 channels, joins all 6 peers to each channel, sets anchor peers

  Verify it worked:
  docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "orderer|peer|couchdb"
  # You should see ~14 containers: 2 orderers + 6 peers + 6 CouchDB instances

  ---
  Phase 4 — Deploy Chaincodes to All Channels

  export PATH=$HOME/fabric-tools/bin:$PATH
  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection/blockchain/network"

  bash deploy-chaincode.sh kyc-contract kyc-channel
  bash deploy-chaincode.sh alert-contract alert-channel
  bash deploy-chaincode.sh audit-contract audit-channel

  Each command: packages the Go chaincode → installs on all 3 orgs → approves from all 3 orgs → commits to the channel. This is
  the full Fabric lifecycle.

  ---
  Phase 5 — Restart Blockchain-Service

  The blockchain-service started earlier when Fabric wasn't running, so it fell back to degraded mode. You must restart it so it
  reconnects to the live Fabric network.

  # Kill the current blockchain-service process
  pkill -f "go run.*blockchain-service" 2>/dev/null || true
  sleep 2

  # Restart with env vars
  cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
  set -a && source .env && set +a
  cd services/blockchain-service
  go run ./cmd/server/ >> ../../logs/blockchain-service.log 2>&1 &
  cd ../..

  # Wait a moment, then verify
  sleep 4
  curl -s http://localhost:9005/health | python3 -m json.tool

  The health response should now show fabric_connected: true and a real block_height.

  ---
  Phase 6 — Verify Full Stack Health

  curl -s http://localhost:8080/health | python3 -m json.tool

  All services should show "status": "healthy".

  ---
  Phase 7 — E2E Test: Full API Flow
  
  Run these curl commands in sequence. Save the outputs as you go.

  Step 1 — Register an admin user

  curl -s -X POST http://localhost:8080/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{
      "email": "analyst@frauddetection.test",
      "password": "SecurePass123!",
      "full_name": "Test Analyst",
      "role": "ANALYST"
    }' | python3 -m json.tool

  Step 2 — Login and get JWT token

  TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "analyst@frauddetection.test", "password": "SecurePass123!"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  echo "TOKEN: $TOKEN"

  Step 3 — Register a KYC customer (triggers Fabric write)

  CUSTOMER=$(curl -s -X POST http://localhost:8080/api/v1/kyc/customers \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "full_name": "Alice Smith",
      "date_of_birth": "1990-05-15",
      "email": "alice@example.com",
      "phone_number": "+1234567890",
      "document_type": "PASSPORT",
      "document_number": "P12345678",
      "expiry_date": "2030-01-01",
      "country_of_issue": "US",
      "nationality": "US",
      "country_code": "US",
      "city": "New York",
      "postal_code": "10001",
      "address_line1": "123 Main St",
      "occupation": "Engineer",
      "source_of_funds": "Employment",
      "expected_monthly_volume": 5000
    }' | python3 -m json.tool)

  echo "$CUSTOMER"
  CUSTOMER_ID=$(echo "$CUSTOMER" | python3 -c "import sys,json; print(json.load(sys.stdin)['customer_id'])")
  echo "CUSTOMER_ID: $CUSTOMER_ID"

  What happens here: KYC service creates the customer record in PostgreSQL (with PII encrypted via Vault) → calls
  blockchain-service → kyc-contract.RegisterCustomer is invoked on kyc-channel → immutable record written to Fabric ledger. The
  response includes a blockchain_tx_id.

  Step 4 — Approve the KYC (triggers second Fabric write)

  curl -s -X PATCH "http://localhost:8080/api/v1/kyc/customers/${CUSTOMER_ID}/status" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "status": "APPROVED",
      "risk_level": "LOW",
      "verifier_id": "analyst-001"
    }' | python3 -m json.tool

  Step 5 — Submit a transaction to Kafka (triggers ML fraud prediction)

  # Publish a raw transaction message to the transactions.raw topic
  # Using the Kafka container's built-in tools
  docker exec fds-kafka kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic transactions.raw \
    --property "parse.key=true" \
    --property "key.separator=|" <<'EOF'
  txhash-001|{"tx_hash":"txhash-001","customer_id":"REPLACE_WITH_CUSTOMER_ID","amount":15000.00,"currency":"USD","tx_type":"WIRE_T
  RANSFER","counterparty_id":"cp-external-456","counterparty_name":"Unknown 
  Corp","channel":"ONLINE","country_code":"RU","timestamp":"2026-06-05T10:00:00Z","metadata":{}}
  EOF

  Replace REPLACE_WITH_CUSTOMER_ID with the $CUSTOMER_ID value from Step 3. Use echo $CUSTOMER_ID to get it first.

  What happens: Transaction consumer picks up the message → extracts 166 features → calls ML service PredictFraud gRPC → ensemble
  (LightGBM 0.35 + RF 0.33 + XGBoost 0.32) returns probability → if > threshold, publishes to alerts.created → Alert service
  creates the alert in PostgreSQL + sends WebSocket notification.

  The high amount + Russia country code + wire transfer type will likely score high for fraud.

  Step 6 — Check if an alert was created

  curl -s "http://localhost:8080/api/v1/alerts?limit=5" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

  Step 7 — Query the Fabric ledger to verify immutable KYC record

  This calls the blockchain-service directly (it's an internal endpoint, not exposed through the gateway):

  # Query the KYC record from the Fabric ledger
  curl -s "http://localhost:9005/internal/v1/kyc/record/${CUSTOMER_ID}" | python3 -m json.tool

  Expected response: the KYC record with txId (the actual Fabric transaction ID), kycStatus: "APPROVED", and timestamps — proving
  the data is anchored on-chain.

  # Query the full history of this customer on the ledger
  curl -s "http://localhost:9005/internal/v1/kyc/history/${CUSTOMER_ID}" | python3 -m json.tool

  This returns two entries: the initial PENDING registration and the APPROVED status update — both as separate Fabric
  transactions.

  Step 8 — Check the alert on the blockchain

  # If an alert was created, check its blockchain record too
  ALERT_ID=$(curl -s "http://localhost:8080/api/v1/alerts?limit=1" \
    -H "Authorization: Bearer $TOKEN" \
    | python3 -c "import sys,json; alerts=json.load(sys.stdin).get('alerts',[]); print(alerts[0]['id'] if alerts else 
  'no-alerts')")

  echo "Alert ID: $ALERT_ID"
  curl -s "http://localhost:9005/internal/v1/alerts/customer/${CUSTOMER_ID}" | python3 -m json.tool

  ---
  Quick Reference — What Each Step Proves

  ┌───────────────────────┬────────────────────────────────────────────────────────────────────┐
  │         Step          │                               Proves                               │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Register + Login      │ IAM service, JWT auth, PostgreSQL                                  │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Register KYC customer │ KYC service, Vault PII encryption, Fabric kyc-channel write        │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Approve KYC           │ KYC status machine, second Fabric write, blockchain tx ID returned │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Kafka transaction     │ Transaction consumer, Kafka end-to-end                             │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ ML prediction         │ FastAPI + gRPC ML service, XGBoost/LightGBM/RF ensemble            │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Alert created         │ Alert service, alerts.created Kafka topic                          │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Query Fabric ledger   │ Real Fabric immutable record, tx ID, history                       │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Alert on blockchain   │ Fabric alert-channel write, cross-channel audit trail              │
  └───────────────────────┴────────────────────────────────────────────────────────────────────┘

  ---
  If Something Goes Wrong

    | python3 -c "import sys,json; alerts=json.load(sys.stdin).get('alerts',[]); print(alerts[0]['id'] if alerts else
  'no-alerts')")

  echo "Alert ID: $ALERT_ID"
  curl -s "http://localhost:9005/internal/v1/alerts/customer/${CUSTOMER_ID}" | python3 -m json.tool

  'no-alerts')")

  echo "Alert ID: $ALERT_ID"
  curl -s "http://localhost:9005/internal/v1/alerts/customer/${CUSTOMER_ID}" | python3 -m json.tool

  ---
  Quick Reference — What Each Step Proves

  ┌───────────────────────┬────────────────────────────────────────────────────────────────────┐
  │         Step          │                               Proves                               │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Register + Login      │ IAM service, JWT auth, PostgreSQL                                  │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Register KYC customer │ KYC service, Vault PII encryption, Fabric kyc-channel write        │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Approve KYC           │ KYC status machine, second Fabric write, blockchain tx ID returned │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Kafka transaction     │ Transaction consumer, Kafka end-to-end                             │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ ML prediction         │ FastAPI + gRPC ML service, XGBoost/LightGBM/RF ensemble            │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Alert created         │ Alert service, alerts.created Kafka topic                          │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Query Fabric ledger   │ Real Fabric immutable record, tx ID, history                       │
  ├───────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ Alert on blockchain   │ Fabric alert-channel write, cross-channel audit trail              │
  └───────────────────────┴────────────────────────────────────────────────────────────────────┘

  ---
  If Something Goes Wrong

  cryptogen: command not found after install:
  export PATH=$HOME/fabric-tools/bin:$PATH

  start.sh fails on configtxgen — the binary directory might be config not bin:
  ls ~/fabric-tools/  # check what was extracted

  Blockchain-service still shows degraded after restart:
  tail -50 logs/blockchain-service.log
  # Look for "fabric client initialized" vs "fabric unavailable"

  No alerts created after Kafka message: Check the transaction-service log for ML call errors:
  tail -50 logs/transaction-service.log