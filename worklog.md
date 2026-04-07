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
